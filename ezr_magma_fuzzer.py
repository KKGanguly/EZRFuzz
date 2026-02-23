#!/usr/bin/env python3
"""
ezr_magma_fuzzer.py - EZR Fuzzer with Magma bug tracking
Improvements:
  1. Havoc mutations  - stack 4-128 operators, correct interesting values
  2. Splice           - chunk overwrite from labeled pool (bias GOOD)
  3. Multi-seed       - k=5 seeds via farthest-point sampling per iteration
  4. Multi-center     - k=5 farthest-point GOOD centers, not mean
  5. EZR seed select  - acquisition function picks seeds, not random
  6. Protect seeds    - never evict best-coverage seed, MAX_MUT=50
  7. Diverse top-k    - batch BO with diversity penalty during acquisition
  8. Diverse acq      - top-k diverse candidates, not single argmax

Usage:
    python3.7 ezr_magma_fuzzer.py --target libpng --duration 3600
"""

import os
import re
import sys
import signal
import argparse
import subprocess
import time
import json
import numpy as np
from typing import List, Optional, Tuple
import pickle
import hashlib
import shutil
import glob

try:
    import torch
    from transformers import AutoTokenizer, AutoModel
except ImportError:
    print("ERROR: transformers/torch not found.")
    sys.exit(1)

# ============================================================================
# Configuration
# ============================================================================

class Config:
    BINS_DIR      = "/magma_out/afl"
    CMPLOG_DIR    = "/magma_out/cmplog"
    AFL_SHOWMAP   = "/magma/fuzzers/aflplusplus/repo/afl-showmap"
    MAGMA_TARGETS = "/magma/targets"
    MONITOR       = "/magma_out/monitor"

    MODEL_NAME    = "sentence-transformers/all-MiniLM-L6-v2"
    MODEL_CACHE   = "/ezr/model_cache"

    EMBEDDING_DIM    = 384
    MAX_INPUT_LENGTH = 512

    MUTATIONS_PER_SEED = 200     # per seed; k seeds -> k*500 total candidates
    BATCH_SIZE         = 128

    WORK_DIR = "/ezr/work"

    MAX_POOL_SIZE          = 200
    MAX_MUTATIONS_PER_SEED = 50   # change 6: was 10
    BEST_COV_SEED_HASH     = None # change 6: never evict this seed

    # Change 3: multi-seed
    N_SEEDS_PER_ITER = 3

    # Change 4: multi-center GOOD
    N_GOOD_CENTERS = 5

    # Change 7/8: diverse top-k acquisition
    TOP_K_ACQUIRE  = 30           # candidates to score-diverse select
    TOP_K_EXECUTE  = 15           # how many we actually run
    DIVERSITY_LAMBDA = 0.3        # weight on diversity term

    # Havoc
    HAVOC_STACK_CHOICES = [4, 8, 16, 32, 64, 128]

    # Interesting values (change 1)
    INTERESTING_8  = [0, 1, 16, 32, 64, 100, 127, 128, 200, 255,
                      -1, -128]
    INTERESTING_16 = [0, 128, 255, 256, 512, 1000, 1024, 4096,
                      32767, 32768, 65535, -1, -32768, -129]
    INTERESTING_32 = [0, 1, 256, 65535, 65536,
                      0x7fffffff, 0x80000000, 0xffffffff,
                      100663045, -100663046, -32769, 32768]

# ============================================================================
# Magma Bug Tracker
# ============================================================================

class BugTracker:
    def __init__(self):
        self.bugs_reached    = set()
        self.bugs_triggered  = set()
        self.trigger_history = []
        self.reach_history   = []
        self.new_cov_events  = 0

    def update(self, reached: frozenset, triggered: frozenset,
               inp: bytes, elapsed: float):
        new_reached   = reached   - self.bugs_reached
        new_triggered = triggered - self.bugs_triggered

        if new_reached:
            self.new_cov_events += 1
            h = hashlib.sha256(inp).hexdigest()[:16]
            print(f"  [NEW BUGS REACHED] {sorted(new_reached)}")
            for b in new_reached:
                self.reach_history.append({'bug': b, 'time': elapsed, 'input_hash': h})

        if new_triggered:
            h = hashlib.sha256(inp).hexdigest()[:16]
            print(f"  [!!!] BUGS TRIGGERED: {sorted(new_triggered)}")
            for b in new_triggered:
                self.trigger_history.append({'bug': b, 'time': elapsed, 'input_hash': h})

        self.bugs_reached   |= reached
        self.bugs_triggered |= triggered
        return bool(new_reached or new_triggered)

    def summary(self) -> dict:
        return {
            'bugs_reached':    sorted(self.bugs_reached),
            'bugs_triggered':  sorted(self.bugs_triggered),
            'n_reached':       len(self.bugs_reached),
            'n_triggered':     len(self.bugs_triggered),
            'new_cov_events':  self.new_cov_events,
            'trigger_history': self.trigger_history,
            'reach_history':   self.reach_history,
        }

# ============================================================================
# Magma Target
# ============================================================================

class MagmaTarget:
    TARGETS = {
        'libpng':  {'program': 'libpng_read_fuzzer'},
        'libtiff': {'program': 'tiff_read_rgba_fuzzer'},
        'libxml2': {'program': 'libxml2_xml_read_memory_fuzzer'},
        'sqlite3': {'program': 'sqlite3_fuzz'},
        'poppler': {'program': 'pdf_fuzzer'},
        'openssl': {'program': 'x509'},
    }

    def __init__(self, target_name: str):
        if target_name not in self.TARGETS:
            raise ValueError(f"Unknown target: {target_name}.")

        self.target_name = target_name
        self.program     = self.TARGETS[target_name]['program']
        self.binary_path = os.path.join(Config.BINS_DIR, self.program)
        self.corpus_path = os.path.join(Config.MAGMA_TARGETS, target_name,
                                        "corpus", self.program)
        self.afl_showmap = Config.AFL_SHOWMAP
        self.use_monitor = os.path.exists(Config.MONITOR)

        self._validate()
        print(f"  Target   : {target_name}")
        print(f"  Binary   : {self.binary_path}")
        print(f"  Corpus   : {self.corpus_path}")
        print(f"  AFL++    : {self.afl_showmap}")
        print(f"  Monitor  : {'YES' if self.use_monitor else 'NO'}")

    def _validate(self):
        errors = []
        if not os.path.exists(self.binary_path):
            errors.append(f"Binary not found: {self.binary_path}")
        if not os.path.exists(self.afl_showmap):
            errors.append(f"afl-showmap not found: {self.afl_showmap}")
        if errors:
            for e in errors:
                print(f"  ! {e}")
            sys.exit(1)
        if not os.path.exists(self.corpus_path):
            os.makedirs(self.corpus_path, exist_ok=True)
            with open(os.path.join(self.corpus_path, "seed_0"), 'wb') as f:
                f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 8)

    def run(self, input_path: str, timeout: int = 2):
        if self.use_monitor:
            return self._run_with_monitor(input_path, timeout)
        else:
            cov = self._run_showmap(input_path, timeout)
            return cov, cov == -1, frozenset(), frozenset()

    def _run_showmap(self, input_path: str, timeout: int) -> int:
        trace = f"/tmp/trace_{os.getpid()}_{int(time.time()*1000)}.txt"
        try:
            env = os.environ.copy()
            env.update({
                "AFL_MAP_SIZE":          "256000",
                "AFL_SKIP_CPUFREQ":      "1",
                "AFL_NO_AFFINITY":       "1",
                "AFL_DRIVER_DONT_DEFER": "1",
                "AFL_NO_UI":             "1",
            })
            result = subprocess.run(
                [self.afl_showmap, '-q', '-o', trace,
                 '-t', str(timeout * 1000), '-m', 'none',
                 '--', self.binary_path, input_path],
                capture_output=True, timeout=timeout + 1, env=env,
            )
            if result.returncode == 35:
                return -1
            if os.path.exists(trace):
                with open(trace, 'r') as f:
                    return len(f.readlines())
            return 0
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            print(f"  [!] showmap error: {e}")
            return None
        finally:
            try:
                os.remove(trace)
            except:
                pass

    def _run_with_monitor(self, input_path: str, timeout: int):
        reached, triggered = set(), set()
        try:
            cmd = [Config.MONITOR, '--fetch', 'watch', '--dump', 'human',
                   self.binary_path, input_path]
            env = os.environ.copy()
            env.update({
                "AFL_MAP_SIZE":          "256000",
                "AFL_SKIP_CPUFREQ":      "1",
                "AFL_NO_AFFINITY":       "1",
                "AFL_DRIVER_DONT_DEFER": "1",
            })
            result = subprocess.run(
                cmd, capture_output=True, timeout=timeout + 1, env=env,
            )
            out = result.stdout.decode('utf-8', 'replace')
            for line in out.splitlines():
                m = re.match(r'([^ ]+) reached ([0-9]+) triggered ([0-9]+)', line)
                if m:
                    bid, r, t = m.group(1), int(m.group(2)), int(m.group(3))
                    if r > 0: reached.add(bid)
                    if t > 0: triggered.add(bid)
            rc = result.returncode
            crashed = (rc < 0 and rc != -(signal.SIGALRM)) or bool(triggered)
            cov = self._run_showmap(input_path, timeout)
        except subprocess.TimeoutExpired:
            return None, False, frozenset(), frozenset()
        except Exception as e:
            print(f"  [!] monitor error: {e}")
            return None, False, frozenset(), frozenset()
        return cov, crashed, frozenset(reached), frozenset(triggered)

# ============================================================================
# Change 1 + 2: Havoc Mutator with Splice
# ============================================================================

class HavocMutator:
    """
    AFL-style havoc mutator:
    - Stacks 4-128 operators per input (change 1)
    - Correct 8/16/32-bit interesting values (change 1)
    - Splice from pool (change 2)
    """

    def __init__(self):
        self.pool_data: List[bytes] = []   # updated externally from labeled pool

    def update_pool(self, pool_data: List[bytes]):
        self.pool_data = pool_data

    def mutate_seed(self, seed_path: str, output_dir: str, count: int) -> List[str]:
        os.makedirs(output_dir, exist_ok=True)
        with open(seed_path, 'rb') as f:
            seed_data = f.read()
        mutations = []
        for i in range(count):
            out_path = os.path.join(output_dir, f"mut_{i:05d}")
            mutated  = self._havoc(seed_data, i)
            with open(out_path, 'wb') as f:
                f.write(mutated)
            mutations.append(out_path)
        return mutations

    def _havoc(self, data: bytes, seed: int) -> bytes:
        rng   = np.random.RandomState(seed)
        data  = bytearray(data)
        n_ops = int(rng.choice(Config.HAVOC_STACK_CHOICES))

        for _ in range(n_ops):
            if not data:
                break
            op = rng.randint(0, 18)

            if op == 0:
                # Flip random bit
                pos = rng.randint(0, len(data))
                data[pos] ^= (1 << rng.randint(0, 8))

            elif op == 1:
                # Random byte <- interesting 8
                pos = rng.randint(0, len(data))
                val = int(rng.choice(Config.INTERESTING_8)) & 0xFF
                data[pos] = val

            elif op == 2:
                # Random word <- interesting 16
                if len(data) >= 2:
                    pos = rng.randint(0, len(data) - 1)
                    val = int(rng.choice(Config.INTERESTING_16)) & 0xFFFF
                    end = 'little' if rng.randint(0, 2) == 0 else 'big'
                    data[pos:pos+2] = val.to_bytes(2, end)

            elif op == 3:
                # Random dword <- interesting 32
                if len(data) >= 4:
                    pos = rng.randint(0, len(data) - 3)
                    val = int(rng.choice(Config.INTERESTING_32)) & 0xFFFFFFFF
                    end = 'little' if rng.randint(0, 2) == 0 else 'big'
                    data[pos:pos+4] = val.to_bytes(4, end)

            elif op == 4:
                # Random byte <- random value
                data[rng.randint(0, len(data))] = rng.randint(0, 256)

            elif op == 5:
                # Subtract random from byte
                pos = rng.randint(0, len(data))
                data[pos] = (data[pos] - rng.randint(1, 36)) % 256

            elif op == 6:
                # Add random to byte
                pos = rng.randint(0, len(data))
                data[pos] = (data[pos] + rng.randint(1, 36)) % 256

            elif op == 7:
                # Subtract random from word
                if len(data) >= 2:
                    pos = rng.randint(0, len(data) - 1)
                    end = 'little' if rng.randint(0, 2) == 0 else 'big'
                    val = int.from_bytes(data[pos:pos+2], end)
                    val = (val - rng.randint(1, 36)) & 0xFFFF
                    data[pos:pos+2] = val.to_bytes(2, end)

            elif op == 8:
                # Add random to word
                if len(data) >= 2:
                    pos = rng.randint(0, len(data) - 1)
                    end = 'little' if rng.randint(0, 2) == 0 else 'big'
                    val = int.from_bytes(data[pos:pos+2], end)
                    val = (val + rng.randint(1, 36)) & 0xFFFF
                    data[pos:pos+2] = val.to_bytes(2, end)

            elif op == 9:
                # Subtract random from dword
                if len(data) >= 4:
                    pos = rng.randint(0, len(data) - 3)
                    end = 'little' if rng.randint(0, 2) == 0 else 'big'
                    val = int.from_bytes(data[pos:pos+4], end)
                    val = (val - rng.randint(1, 36)) & 0xFFFFFFFF
                    data[pos:pos+4] = val.to_bytes(4, end)

            elif op == 10:
                # Add random to dword
                if len(data) >= 4:
                    pos = rng.randint(0, len(data) - 3)
                    end = 'little' if rng.randint(0, 2) == 0 else 'big'
                    val = int.from_bytes(data[pos:pos+4], end)
                    val = (val + rng.randint(1, 36)) & 0xFFFFFFFF
                    data[pos:pos+4] = val.to_bytes(4, end)

            elif op == 11:
                # XOR random byte
                pos = rng.randint(0, len(data))
                data[pos] ^= rng.randint(1, 256)

            elif op == 12:
                # Memset random region
                if len(data) >= 2:
                    pos = rng.randint(0, len(data) - 1)
                    length = rng.randint(1, min(32, len(data) - pos) + 1)
                    fill = rng.randint(0, 256)
                    data[pos:pos+length] = bytes([fill] * length)

            elif op == 13:
                # Copy chunk to random position (overwrite)
                if len(data) >= 4:
                    src = rng.randint(0, len(data) - 2)
                    length = rng.randint(1, min(32, len(data) - src) + 1)
                    dst = rng.randint(0, len(data) - length + 1)
                    chunk = data[src:src+length]
                    data[dst:dst+length] = chunk

            elif op == 14:
                # Delete random chunk
                if len(data) > 4:
                    pos = rng.randint(0, len(data) - 2)
                    length = rng.randint(1, min(32, len(data) - pos) + 1)
                    del data[pos:pos+length]

            elif op == 15:
                # Insert random bytes
                pos = rng.randint(0, len(data) + 1)
                length = rng.randint(1, 16)
                insert = bytes([rng.randint(0, 256) for _ in range(length)])
                data = data[:pos] + bytearray(insert) + data[pos:]

            elif op == 16:
                # Overwrite with chunk from same input
                if len(data) >= 4:
                    src = rng.randint(0, len(data) - 2)
                    length = rng.randint(1, min(32, len(data) - src) + 1)
                    dst = rng.randint(0, len(data) - length + 1)
                    data[dst:dst+length] = data[src:src+length]

            elif op == 17:
                # Change 2: Splice from pool
                if self.pool_data:
                    donor = bytearray(self.pool_data[rng.randint(0, len(self.pool_data))])
                    if len(donor) >= 2 and len(data) >= 2:
                        split_d = rng.randint(1, len(data))
                        split_s = rng.randint(1, len(donor))
                        data = data[:split_d] + donor[split_s:]

        return bytes(data)

# ============================================================================
# LLM Encoder
# ============================================================================

class LLMEncoder:
    def __init__(self):
        print(f"[*] Loading model: {Config.MODEL_NAME}")
        self.tokenizer = AutoTokenizer.from_pretrained(
            Config.MODEL_NAME, cache_dir=Config.MODEL_CACHE, local_files_only=True)
        self.model = AutoModel.from_pretrained(
            Config.MODEL_NAME, cache_dir=Config.MODEL_CACHE, local_files_only=True)
        self.model.eval()
        print("[+] Model loaded.")

    def encode_batch(self, data_list: list) -> np.ndarray:
        # Position-weighted hex: head bytes matter more (change: better representation)
        hex_strs = []
        for d in data_list:
            head = d[:128].hex()          # first 128 bytes - magic/header
            tail = d[128:256].hex()       # next 128 bytes
            hex_strs.append(head + " " + tail)
        with torch.no_grad():
            inputs  = self.tokenizer(hex_strs, return_tensors="pt", padding=True,
                                     truncation=True, max_length=512)
            outputs = self.model(**inputs)
        return outputs.last_hidden_state.mean(dim=1).cpu().numpy()

# ============================================================================
# Change 4 + 7 + 8: EZR Acquisition with multi-center and diverse top-k
# ============================================================================

class EZRAcquisition:
    """
    Change 4: k farthest-point GOOD centers instead of single mean
    Change 7: diverse top-k selection with diversity penalty
    Change 8: acquire top-k diverse candidates, not single argmax
    """

    def __init__(self, n_centers: int = Config.N_GOOD_CENTERS):
        self.good_embeddings: List[np.ndarray] = []
        self.rest_embeddings: List[np.ndarray] = []
        self.good_centers:    Optional[np.ndarray] = None  # (k, D)
        self.rest_center:     Optional[np.ndarray] = None
        self.n_centers = n_centers

    def _farthest_point_centers(self, embeddings: List[np.ndarray], k: int) -> np.ndarray:
        """Pick k maximally spread centers from embeddings."""
        embs = np.array(embeddings)
        if len(embs) <= k:
            return embs
        # Start with random point
        centers = [embs[np.random.randint(len(embs))]]
        for _ in range(k - 1):
            # Distance from each point to nearest existing center
            dists = np.min(
                np.stack([np.linalg.norm(embs - c, axis=1) for c in centers]),
                axis=0
            )
            centers.append(embs[int(np.argmax(dists))])
        return np.array(centers)

    def add_good(self, emb: np.ndarray):
        self.good_embeddings.append(emb)
        self.good_centers = self._farthest_point_centers(
            self.good_embeddings, self.n_centers
        )

    def add_rest(self, emb: np.ndarray):
        self.rest_embeddings.append(emb)
        self.rest_center = np.mean(self.rest_embeddings, axis=0)

    def rebuild_centers(self):
        if self.good_embeddings:
            self.good_centers = self._farthest_point_centers(
                self.good_embeddings, self.n_centers
            )
        if self.rest_embeddings:
            self.rest_center = np.mean(self.rest_embeddings, axis=0)

    def score(self, embeddings: np.ndarray) -> np.ndarray:
        """EZR acquisition score for each embedding."""
        if self.good_centers is None:
            return np.random.rand(len(embeddings))

        # Distance to nearest GOOD center (change 4: multi-center)
        dist_good = np.min(
            np.stack([np.linalg.norm(embeddings - c, axis=1)
                      for c in self.good_centers]),
            axis=0
        )
        dist_rest = (
            np.linalg.norm(embeddings - self.rest_center, axis=1)
            if self.rest_center is not None
            else np.ones(len(embeddings))
        )
        return dist_rest - dist_good

    def select_diverse_topk(self, embeddings: np.ndarray,
                             k: int = Config.TOP_K_ACQUIRE,
                             lam: float = Config.DIVERSITY_LAMBDA) -> List[int]:
        """
        Change 7 + 8: Greedy diverse batch acquisition.
        Selects k candidates maximizing acquisition score + diversity.
        """
        scores    = self.score(embeddings)
        selected  = []
        remaining = list(range(len(embeddings)))

        # Always take the best first
        best = int(np.argmax(scores))
        selected.append(best)
        remaining.remove(best)

        while len(selected) < k and remaining:
            cands      = np.array(remaining)
            acq        = scores[cands]
            # Min distance to any already-selected embedding
            diversity  = np.min(
                np.stack([np.linalg.norm(embeddings[cands] - embeddings[s], axis=1)
                          for s in selected]),
                axis=0
            )
            combined   = acq + lam * diversity
            next_local = int(np.argmax(combined))
            next_idx   = int(cands[next_local])
            selected.append(next_idx)
            remaining.remove(next_idx)

        return selected

    def save(self, path: str):
        with open(path, 'wb') as f:
            pickle.dump({
                'good_embeddings': self.good_embeddings,
                'rest_embeddings': self.rest_embeddings,
                'good_centers':    self.good_centers,
                'rest_center':     self.rest_center,
            }, f)

    def load(self, path: str):
        with open(path, 'rb') as f:
            d = pickle.load(f)
        self.good_embeddings = d['good_embeddings']
        self.rest_embeddings = d['rest_embeddings']
        self.good_centers    = d['good_centers']
        self.rest_center     = d['rest_center']

# ============================================================================
# Change 3 + 5: Multi-Seed Selection via Farthest-Point + EZR
# ============================================================================

class SeedSelector:
    """
    Change 3: Select k diverse seeds per iteration using farthest-point sampling.
    Change 5: Use EZR acquisition score to bias toward interesting seeds.
    """

    def select(self,
               pool: list,
               acquisition: EZRAcquisition,
               encoder: LLMEncoder,
               k: int = Config.N_SEEDS_PER_ITER) -> List[str]:
        """
        Returns k seed paths selected by EZR score + farthest-point diversity.
        pool entries: (coverage, embedding_list, path, hash)
        """
        if not pool:
            return []

        paths  = [x[2] for x in pool]
        embs   = np.array([x[1] for x in pool])

        # Change 5: score all pool inputs with EZR acquisition
        scores = acquisition.score(embs)

        selected_idx   = []
        remaining      = list(range(len(pool)))

        # Pick best EZR score first
        best = int(np.argmax(scores))
        selected_idx.append(best)
        remaining.remove(best)

        # Subsequent: maximize EZR score + diversity from already selected
        while len(selected_idx) < min(k, len(pool)) and remaining:
            cands     = np.array(remaining)
            acq       = scores[cands]
            diversity = np.min(
                np.stack([np.linalg.norm(embs[cands] - embs[s], axis=1)
                          for s in selected_idx]),
                axis=0
            )
            combined  = acq + Config.DIVERSITY_LAMBDA * diversity
            next_local = int(np.argmax(combined))
            next_idx   = int(cands[next_local])
            selected_idx.append(next_idx)
            remaining.remove(next_idx)

        return [paths[i] for i in selected_idx]

# ============================================================================
# Main Fuzzer
# ============================================================================

class EZRMagmaFuzzer:
    def __init__(self, target_name: str):
        print(f"\n{'='*70}")
        print("EZR Magma Fuzzer - Initializing (8 improvements active)")
        print(f"{'='*70}\n")

        self.magma         = MagmaTarget(target_name)
        self.bug_tracker   = BugTracker()
        self.work_dir      = Config.WORK_DIR

        self.seeds_dir = os.path.join(self.work_dir, "seeds")
        self.good_dir  = os.path.join(self.work_dir, "good")
        self.rest_dir  = os.path.join(self.work_dir, "rest")
        self.queue_dir = os.path.join(self.work_dir, "queue")
        self.crash_dir = os.path.join(self.work_dir, "crashes")
        self.best_dir  = os.path.join(self.work_dir, "best_inputs")
        for d in [self.seeds_dir, self.good_dir, self.rest_dir,
                  self.queue_dir, self.crash_dir, self.best_dir]:
            os.makedirs(d, exist_ok=True)

        self.encoder       = LLMEncoder()
        self.mutator       = HavocMutator()          # change 1+2
        self.acquisition   = EZRAcquisition()        # change 4+7+8
        self.seed_selector = SeedSelector()          # change 3+5
        self.seeds         = self._load_corpus()

        self.baseline_coverage = 0
        self.best_coverage     = 0
        self.best_cov_hash     = None                # change 6
        self.iteration         = 0
        self.start_time        = None
        self.stats = {
            'iterations': 0,
            'executions': 0,
            'good_inputs': 0,
            'rest_inputs': 0,
            'crashes':     0,
        }
        self.labeled_pool    = []   # (cov, emb_list, path, hash)
        self.mutation_counts = {}

        self._warmup()
        print("\n[+] EZR Magma Fuzzer ready.\n")

    def _load_corpus(self) -> list:
        seeds        = []
        corpus_files = [f for f in glob.glob(
            os.path.join(self.magma.corpus_path, "*")) if os.path.isfile(f)][:100]
        for src in corpus_files:
            dst = os.path.join(self.seeds_dir, os.path.basename(src))
            shutil.copy(src, dst)
            seeds.append(dst)
        if not seeds:
            minimal = os.path.join(self.seeds_dir, "minimal")
            with open(minimal, 'wb') as f:
                f.write(b'\x00' * 16)
            seeds.append(minimal)
        print(f"[+] Loaded {len(seeds)} seeds.")
        return seeds

    def _warmup(self):
        print("[*] Warming up: running 4 seeds to initialize GOOD/REST centers...")
        warmup_seeds = []
        if len(self.seeds) >= 4:
            warmup_seeds = self.seeds[:4]
        else:
            warmup_dir = os.path.join(self.work_dir, "warmup")
            muts = self.mutator.mutate_seed(self.seeds[0], warmup_dir, 20)
            warmup_seeds = [self.seeds[0]] + muts[:3]

        results = []
        for i, seed in enumerate(warmup_seeds):
            cov, crashed, reached, triggered = self.magma.run(seed)
            cov = cov or 0
            emb = self.encoder.encode_batch([open(seed, 'rb').read()])[0]
            results.append((cov, emb, seed))
            print(f"  Seed {i+1}/4: cov={cov} reached={len(reached)} triggered={len(triggered)}")

        results.sort(key=lambda x: x[0], reverse=True)

        for cov, emb, seed in results[:2]:
            self.acquisition.add_good(emb)
            print(f"  -> GOOD: {os.path.basename(seed)} ({cov} edges)")

        for cov, emb, seed in results[2:]:
            self.acquisition.add_rest(emb)
            print(f"  -> REST: {os.path.basename(seed)} ({cov} edges)")

        self.baseline_coverage = results[-1][0]
        self.best_coverage     = results[0][0]

        for cov, emb, seed in results:
            h = hashlib.sha256(open(seed, 'rb').read()).hexdigest()[:16]
            self.labeled_pool.append((cov, emb.tolist(), seed, h))

        # Change 6: track best coverage seed
        best_seed = results[0][2]
        self.best_cov_hash = hashlib.sha256(open(best_seed, 'rb').read()).hexdigest()[:16]

        print(f"[+] Warmup done. best_cov={self.best_coverage}\n")

    def _pool_size_info(self):
        n         = len(self.labeled_pool)
        good_size = max(1, int(np.sqrt(n)))
        return n, good_size

    def _update_mutator_pool(self):
        """Keep mutator's splice pool updated from GOOD inputs."""
        n, good_size = self._pool_size_info()
        good_paths   = [x[2] for x in self.labeled_pool[:good_size]]
        pool_data    = []
        for p in good_paths:
            try:
                with open(p, 'rb') as f:
                    pool_data.append(f.read())
            except Exception:
                pass
        self.mutator.update_pool(pool_data)   # change 2

    def run_iteration(self):
        self.iteration += 1
        elapsed  = int(time.time() - self.start_time)
        print(f"\n[Iter {self.iteration} | {elapsed}s]")

        # Change 3 + 5: select k diverse seeds using EZR acquisition
        if self.labeled_pool:
            selected_seeds = self.seed_selector.select(
                self.labeled_pool, self.acquisition, self.encoder,
                k=Config.N_SEEDS_PER_ITER
            )
        else:
            selected_seeds = self.seeds[:Config.N_SEEDS_PER_ITER]

        print(f"  Seeds selected: {len(selected_seeds)}")

        # Update splice pool before mutating (change 2)
        self._update_mutator_pool()

        # Generate mutations from all selected seeds, pool together
        all_mutations  = []
        all_seed_names = []
        for seed in selected_seeds:
            seed_hash = hashlib.sha256(open(seed, 'rb').read()).hexdigest()[:16]
            self.mutation_counts[seed_hash] = self.mutation_counts.get(seed_hash, 0) + 1

            # Change 6: never evict best coverage seed
            if (self.mutation_counts[seed_hash] > Config.MAX_MUTATIONS_PER_SEED
                    and seed_hash != self.best_cov_hash):
                self.labeled_pool = [x for x in self.labeled_pool if x[3] != seed_hash]
                print(f"  [evict-stale] {seed_hash}")
                continue

            mut_dir   = os.path.join(self.queue_dir,
                                     f"iter_{self.iteration}_{seed_hash[:8]}")
            mutations = self.mutator.mutate_seed(
                seed, mut_dir, Config.MUTATIONS_PER_SEED)
            all_mutations.extend(mutations)
            all_seed_names.extend([os.path.basename(seed)] * len(mutations))

        if not all_mutations:
            print("  [!] No mutations generated, skipping.")
            return

        print(f"  Total mutations: {len(all_mutations)}")

        # Embed all mutations in batches
        print(f"  Embedding {len(all_mutations)} mutations...")
        embeddings_list = []
        for i in range(0, len(all_mutations), Config.BATCH_SIZE):
            batch      = all_mutations[i:i + Config.BATCH_SIZE]
            batch_data = []
            for m in batch:
                try:
                    with open(m, 'rb') as f:
                        batch_data.append(f.read())
                except Exception:
                    batch_data.append(b'\x00')
            embeddings_list.append(self.encoder.encode_batch(batch_data))
            print(f"    {min(i + Config.BATCH_SIZE, len(all_mutations))}/{len(all_mutations)}")
        embeddings = np.vstack(embeddings_list)

        # Change 7 + 8: diverse top-k acquisition (not single argmax)
        top_k_idx = self.acquisition.select_diverse_topk(
            embeddings,
            k=Config.TOP_K_ACQUIRE,
            lam=Config.DIVERSITY_LAMBDA
        )
        # Execute only TOP_K_EXECUTE of those
        exec_idx = top_k_idx[:Config.TOP_K_EXECUTE]
        print(f"  Executing {len(exec_idx)} diverse candidates...")

        best_coverage_iter = 0
        best_idx           = exec_idx[0]
        best_embedding     = embeddings[best_idx]
        reached_all        = frozenset()
        triggered_all      = frozenset()

        for idx in exec_idx:
            inp       = all_mutations[idx]
            try:
                inp_bytes = open(inp, 'rb').read()
            except Exception:
                continue
            cov, crashed, reached, triggered = self.magma.run(inp)
            self.stats['executions'] += 1

            reached_all   = reached_all   | reached
            triggered_all = triggered_all | triggered

            if crashed:
                self.stats['crashes'] += 1
                h2 = hashlib.sha256(inp_bytes).hexdigest()[:16]
                shutil.copy(inp, os.path.join(
                    self.crash_dir, f"crash_{self.stats['crashes']:04d}_{h2}"))
                print(f"  [!!!] CRASH #{self.stats['crashes']}")

            if cov and cov > best_coverage_iter:
                best_coverage_iter = cov
                best_idx           = idx
                best_embedding     = embeddings[idx]

        # Final run on best to confirm coverage + bugs
        best_input       = all_mutations[best_idx]
        try:
            best_input_bytes = open(best_input, 'rb').read()
        except Exception:
            best_input_bytes = b''
        h = hashlib.sha256(best_input_bytes).hexdigest()[:16]

        coverage, crashed, reached, triggered = self.magma.run(best_input)
        self.stats['executions'] += 1
        reached_all   = reached_all   | reached
        triggered_all = triggered_all | triggered

        # Save best input permanently
        perm_path = os.path.join(self.best_dir, f"iter_{self.iteration}_{h}")
        try:
            shutil.copy(best_input, perm_path)
        except Exception:
            perm_path = best_input
        best_input = perm_path

        # Bug tracking
        elapsed_f = time.time() - self.start_time
        self.bug_tracker.update(reached_all, triggered_all, best_input_bytes, elapsed_f)

        # Crash handling
        if crashed or coverage == -1:
            self.stats['crashes'] += 1
            crash_path = os.path.join(self.crash_dir,
                                      f"crash_{self.stats['crashes']:04d}_{h}")
            try:
                shutil.copy(best_input, crash_path)
            except Exception:
                pass
            print(f"  [!!!] CRASH #{self.stats['crashes']}")

        if coverage is None:
            print("  [T] Timeout - skipping")
            self._cleanup_mut_dirs()
            return
        if coverage == -1:
            coverage = 0

        # Change 6: track and protect best coverage seed
        if coverage > self.best_coverage:
            self.best_coverage = coverage
            self.best_cov_hash = h
            print(f"  [!!!] NEW BEST: {coverage} edges  seed protected from eviction")

        # Add to labeled pool
        self.labeled_pool.append((coverage, best_embedding.tolist(), best_input, h))
        self.labeled_pool.sort(key=lambda x: x[0], reverse=True)

        n, good_size = self._pool_size_info()

        # Rebuild acquisition centers
        self.acquisition.good_embeddings = []
        self.acquisition.rest_embeddings = []
        for cov_i, emb_i, path_i, fh_i in self.labeled_pool[:good_size]:
            self.acquisition.add_good(np.array(emb_i))
        for cov_i, emb_i, path_i, fh_i in self.labeled_pool[good_size:]:
            self.acquisition.add_rest(np.array(emb_i))

        # Evict by size but never evict best coverage seed (change 6)
        if len(self.labeled_pool) > Config.MAX_POOL_SIZE:
            protected = [x for x in self.labeled_pool if x[3] == self.best_cov_hash]
            rest_pool = [x for x in self.labeled_pool if x[3] != self.best_cov_hash]
            rest_pool = rest_pool[:Config.MAX_POOL_SIZE - len(protected)]
            self.labeled_pool = protected + rest_pool
            self.labeled_pool.sort(key=lambda x: x[0], reverse=True)
            n, good_size = self._pool_size_info()
            print(f"  [evict-size] Pool capped at {Config.MAX_POOL_SIZE}")

        self.stats['good_inputs'] = good_size
        self.stats['rest_inputs'] = n - good_size

        # Label current best input
        current_idx = good_size
        for i, (cov_i, emb_i, path_i, fh_i) in enumerate(self.labeled_pool):
            if fh_i == h:
                current_idx = i
                break
        current_label = "GOOD" if current_idx < good_size else "REST"

        print(f"  -> {current_label} | cov={coverage} best={self.best_coverage} "
              f"GOOD={good_size} REST={n - good_size}")

        if current_label == "GOOD":
            dst = os.path.join(self.good_dir, f"good_{self.iteration}_{h}")
            try:
                shutil.copy(best_input, dst)
            except Exception:
                pass
            if dst not in self.seeds:
                self.seeds.append(dst)
        else:
            dst = os.path.join(self.rest_dir, f"rest_{self.iteration}_{h}")
            try:
                shutil.copy(best_input, dst)
            except Exception:
                pass

        self.stats['iterations'] = self.iteration
        self._cleanup_mut_dirs()

    def _cleanup_mut_dirs(self):
        for d in glob.glob(os.path.join(self.queue_dir, f"iter_{self.iteration}_*")):
            shutil.rmtree(d, ignore_errors=True)

    def _print_stats(self, elapsed, remaining):
        sep  = '=' * 66
        dash = '-' * 66
        bt   = self.bug_tracker
        print(f"\n  {sep}")
        print(f"  STATS | elapsed={elapsed}s remaining={remaining}s")
        print(f"  {dash}")
        print(f"  Iterations   : {self.stats['iterations']}")
        print(f"  Executions   : {self.stats['executions']}")
        print(f"  Best cov     : {self.best_coverage} edges")
        print(f"  Good inputs  : {self.stats['good_inputs']}")
        print(f"  Rest inputs  : {self.stats['rest_inputs']}")
        print(f"  Crashes      : {self.stats['crashes']}")
        print(f"  {dash}")
        print(f"  Bugs reached : {len(bt.bugs_reached)}  {sorted(bt.bugs_reached)}")
        print(f"  Bugs trigg.  : {len(bt.bugs_triggered)}  {sorted(bt.bugs_triggered)}")
        print(f"  New cov evts : {bt.new_cov_events}")
        if bt.trigger_history:
            print(f"  Trigger log  :")
            for t in bt.trigger_history:
                print(f"    [{t['time']:.0f}s] {t['bug']}  input={t['input_hash']}")
        print(f"  {sep}\n")

    def run(self, duration: int):
        print(f"[*] Campaign duration: {duration}s")
        self.start_time = time.time()
        end = self.start_time + duration

        try:
            while time.time() < end:
                self.run_iteration()
                elapsed   = int(time.time() - self.start_time)
                remaining = int(end - time.time())
                self._print_stats(elapsed, remaining)
                if self.iteration % 5 == 0:
                    self.acquisition.save(os.path.join(self.work_dir, "ezr_state.pkl"))
                    self._save_report()
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")

        self._save_report()
        self._print_final()

    def _save_report(self):
        report = {
            'fuzzer':             'ezr_magma_v2',
            'target':             self.magma.target_name,
            'elapsed_s':          int(time.time() - self.start_time),
            **self.stats,
            **self.bug_tracker.summary(),
            'best_coverage':      self.best_coverage,
            'baseline_coverage':  self.baseline_coverage,
        }
        path = os.path.join(self.work_dir, "ezr_report.json")
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)

    def _print_final(self):
        sep = '=' * 70
        bt  = self.bug_tracker
        print(f"\n{sep}")
        print("Campaign complete!")
        print(sep)
        print(f"  Iterations     : {self.stats['iterations']}")
        print(f"  Executions     : {self.stats['executions']}")
        print(f"  Good inputs    : {self.stats['good_inputs']}")
        print(f"  Rest inputs    : {self.stats['rest_inputs']}")
        print(f"  Crashes        : {self.stats['crashes']}")
        print(f"  Best coverage  : {self.best_coverage} edges")
        print(f"  Bugs reached   : {len(bt.bugs_reached)}  {sorted(bt.bugs_reached)}")
        print(f"  Bugs triggered : {len(bt.bugs_triggered)}  {sorted(bt.bugs_triggered)}")
        print(f"  Results        : {self.work_dir}")
        print(f"  Report         : {self.work_dir}/ezr_report.json")
        print(sep)

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="EZR Fuzzer with Magma (v2)")
    parser.add_argument('--target', required=True,
                        choices=list(MagmaTarget.TARGETS.keys()))
    parser.add_argument('--duration', type=int, default=3600)
    args = parser.parse_args()

    fuzzer = EZRMagmaFuzzer(args.target)
    fuzzer.run(args.duration)

if __name__ == "__main__":
    main()