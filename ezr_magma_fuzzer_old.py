#!/usr/bin/env python3
"""
ezr_magma_fuzzer.py - EZR Fuzzer with Magma bug tracking
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
from typing import List, Optional
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
    MONITOR       = "/magma_out/monitor"   # Magma bug monitor binary

    MODEL_NAME    = "sentence-transformers/all-MiniLM-L6-v2"
    MODEL_CACHE   = "/ezr/model_cache"

    EMBEDDING_DIM    = 384
    MAX_INPUT_LENGTH = 512

    MUTATIONS_PER_SEED = 1000
    BATCH_SIZE         = 1000

    WORK_DIR = "/ezr/work"

    MAX_POOL_SIZE = 200
    MAX_MUTATIONS_PER_SEED = 10

# ============================================================================
# Magma Bug Tracker (from SOGO-RL)
# ============================================================================

class BugTracker:
    """Tracks which Magma bugs have been reached and triggered."""

    def __init__(self):
        self.bugs_reached   = set()
        self.bugs_triggered = set()
        self.trigger_history = []   # list of (timestamp, bug_id, input_hash)
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
                self.reach_history.append({
                    'bug': b, 'time': elapsed, 'input_hash': h
                })

        if new_triggered:
            h = hashlib.sha256(inp).hexdigest()[:16]
            print(f"  [!!!] BUGS TRIGGERED: {sorted(new_triggered)}")
            for b in new_triggered:
                self.trigger_history.append({
                    'bug': b, 'time': elapsed, 'input_hash': h
                })

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

        self.target_name  = target_name
        self.program      = self.TARGETS[target_name]['program']
        self.binary_path  = os.path.join(Config.BINS_DIR, self.program)
        self.corpus_path  = os.path.join(Config.MAGMA_TARGETS, target_name, "corpus", self.program)
        self.afl_showmap  = Config.AFL_SHOWMAP
        self.use_monitor  = os.path.exists(Config.MONITOR)

        self._validate()

        print(f"  Target   : {target_name}")
        print(f"  Binary   : {self.binary_path}")
        print(f"  Corpus   : {self.corpus_path}")
        print(f"  AFL++    : {self.afl_showmap}")
        print(f"  Monitor  : {'YES - Magma bug tracking active' if self.use_monitor else 'NO - coverage only'}")

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
        """
        Run target. Returns (coverage, crashed, reached_bugs, triggered_bugs).
        Uses Magma monitor if available, otherwise falls back to afl-showmap.
        """
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
            # afl-showmap returns 35 on crash
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
            try: os.remove(trace)
            except: pass

    def _run_with_monitor(self, input_path: str, timeout: int):
        """Run with Magma monitor to get bug reach/trigger info."""
        reached, triggered = set(), set()
        crashed = False
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
                cmd, capture_output=True,
                timeout=timeout + 1, env=env,
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
            # Get coverage too
            cov = self._run_showmap(input_path, timeout)
        except subprocess.TimeoutExpired:
            return None, False, frozenset(), frozenset()
        except Exception as e:
            print(f"  [!] monitor error: {e}")
            return None, False, frozenset(), frozenset()

        return cov, crashed, frozenset(reached), frozenset(triggered)

# ============================================================================
# Mutator
# ============================================================================

class AFLMutator:
    def mutate_seed(self, seed_path: str, output_dir: str, count: int) -> list:
        os.makedirs(output_dir, exist_ok=True)
        with open(seed_path, 'rb') as f:
            seed_data = f.read()
        mutations = []
        for i in range(count):
            out_path = os.path.join(output_dir, f"mut_{i:05d}")
            with open(out_path, 'wb') as f:
                f.write(self._mutate(seed_data, i))
            mutations.append(out_path)
        return mutations

    def _mutate(self, data: bytes, seed: int) -> bytes:
        np.random.seed(seed)
        data     = bytearray(data)
        if not data:
            return bytes(data)
        mut_type = seed % 8
        if mut_type == 0:
            pos = np.random.randint(0, len(data))
            data[pos] ^= (1 << np.random.randint(0, 8))
        elif mut_type == 1:
            data[np.random.randint(0, len(data))] ^= 0xFF
        elif mut_type == 2:
            pos = np.random.randint(0, len(data))
            data[pos] = (data[pos] + np.random.randint(-35, 36)) % 256
        elif mut_type == 3:
            data[np.random.randint(0, len(data))] = np.random.choice([0,1,16,32,64,100,127,255])
        elif mut_type == 4:
            pos   = np.random.randint(0, len(data) + 1)
            token = np.random.choice([b'\x00', b'\xFF', b'\r\n', b'</>'])
            data  = data[:pos] + token + data[pos:]
        elif mut_type == 5:
            if len(data) > 4:
                p1 = np.random.randint(0, len(data) - 2)
                p2 = np.random.randint(p1 + 1, len(data))
                data = data[:p1] + data[p2:]
        elif mut_type == 6:
            if len(data) > 4:
                p1    = np.random.randint(0, len(data) - 2)
                p2    = np.random.randint(p1 + 1, len(data))
                chunk = data[p1:p2]
                ins   = np.random.randint(0, len(data) + 1)
                data  = data[:ins] + chunk + data[ins:]
        elif mut_type == 7:
            data[np.random.randint(0, len(data))] = np.random.randint(0, 256)
        return bytes(data)

# ============================================================================
# LLM Encoder
# ============================================================================

class LLMEncoder:
    def __init__(self):
        print(f"[*] Loading model from cache: {Config.MODEL_CACHE}")
        self.tokenizer = AutoTokenizer.from_pretrained(
            Config.MODEL_NAME, cache_dir=Config.MODEL_CACHE, local_files_only=True)
        self.model = AutoModel.from_pretrained(
            Config.MODEL_NAME, cache_dir=Config.MODEL_CACHE, local_files_only=True)
        self.model.eval()
        print("[+] Model loaded.")

    def encode_batch(self, data_list: list) -> np.ndarray:
        hex_strs = [d[:Config.MAX_INPUT_LENGTH].hex() for d in data_list]
        with torch.no_grad():
            inputs  = self.tokenizer(hex_strs, return_tensors="pt", padding=True,
                                     truncation=True, max_length=512)
            outputs = self.model(**inputs)
        return outputs.last_hidden_state.mean(dim=1).cpu().numpy()

# ============================================================================
# EZR Acquisition
# ============================================================================

class EZRAcquisition:
    def __init__(self):
        self.good_embeddings = []
        self.rest_embeddings = []
        self.good_center     = None
        self.rest_center     = None

    def add_good(self, emb: np.ndarray):
        self.good_embeddings.append(emb)
        self.good_center = np.mean(self.good_embeddings, axis=0)

    def add_rest(self, emb: np.ndarray):
        self.rest_embeddings.append(emb)
        self.rest_center = np.mean(self.rest_embeddings, axis=0)

    def select_best(self, embeddings: np.ndarray) -> int:
        if self.good_center is None and self.rest_center is None:
            return np.random.randint(0, len(embeddings))
        dist_good = np.linalg.norm(embeddings - self.good_center, axis=1) \
                    if self.good_center is not None else np.zeros(len(embeddings))
        dist_rest = np.linalg.norm(embeddings - self.rest_center, axis=1) \
                    if self.rest_center is not None else np.ones(len(embeddings)) * 1e9
        return int(np.argmax(dist_rest - dist_good))

    def save(self, path: str):
        with open(path, 'wb') as f:
            pickle.dump({
                'good_embeddings': self.good_embeddings,
                'rest_embeddings': self.rest_embeddings,
                'good_center':     self.good_center,
                'rest_center':     self.rest_center,
            }, f)

# ============================================================================
# Main Fuzzer
# ============================================================================

class EZRMagmaFuzzer:
    def __init__(self, target_name: str):
        print(f"\n{'='*70}")
        print("EZR Magma Fuzzer - Initializing")
        print(f"{'='*70}\n")

        self.magma       = MagmaTarget(target_name)
        self.bug_tracker = BugTracker()
        self.work_dir    = Config.WORK_DIR

        self.seeds_dir   = os.path.join(self.work_dir, "seeds")
        self.good_dir    = os.path.join(self.work_dir, "good")
        self.rest_dir    = os.path.join(self.work_dir, "rest")
        self.queue_dir   = os.path.join(self.work_dir, "queue")
        self.crash_dir   = os.path.join(self.work_dir, "crashes")
        for d in [self.seeds_dir, self.good_dir, self.rest_dir,
                  self.queue_dir, self.crash_dir]:
            os.makedirs(d, exist_ok=True)

        self.encoder     = LLMEncoder()
        self.mutator     = AFLMutator()
        self.acquisition = EZRAcquisition()
        self.seeds       = self._load_corpus()

        self.baseline_coverage = 0
        self.best_coverage     = 0
        self.iteration         = 0
        self.start_time        = None
        self.stats = {
            'iterations': 0,
            'executions': 0,
            'good_inputs': 0,
            'rest_inputs': 0,
            'crashes': 0,
        }
        self.labeled_pool = []
        self.mutation_counts = {}
        self._warmup()
        print("\n[+] EZR Magma Fuzzer ready.\n")

    def _load_corpus(self) -> list:
        seeds        = []
        corpus_files = [f for f in glob.glob(os.path.join(self.magma.corpus_path, "*"))
                        if os.path.isfile(f)][:100]
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
        """Run 4 seeds, rank by coverage, top 2 -> GOOD, bottom 2 -> REST."""
        print("[*] Warming up: running 4 seeds to initialize GOOD/REST centers...")

        # Generate 4 varied mutations of the first seed for warmup diversity
        warmup_seeds = []
        if len(self.seeds) >= 4:
            warmup_seeds = self.seeds[:4]
        else:
            mutator = AFLMutator()
            base = self.seeds[0]
            warmup_dir = os.path.join(self.work_dir, "warmup")
            muts = mutator.mutate_seed(base, warmup_dir, 20)
            warmup_seeds = [base] + muts[:3]  # original + 3 mutations

        results = []
        for i, seed in enumerate(warmup_seeds):
            cov, crashed, reached, triggered = self.magma.run(seed)
            cov = cov or 0
            emb = self.encoder.encode_batch([open(seed, 'rb').read()])[0]
            results.append((cov, emb, seed))
            print(f"  Seed {i+1}/4: {os.path.basename(seed)} -> {cov} edges  "
                  f"reached={len(reached)} triggered={len(triggered)}")

        results.sort(key=lambda x: x[0], reverse=True)

        for cov, emb, seed in results[:2]:
            self.acquisition.add_good(emb)
            print(f"  -> GOOD: {os.path.basename(seed)} ({cov} edges)")

        for cov, emb, seed in results[2:]:
            self.acquisition.add_rest(emb)
            print(f"  -> REST: {os.path.basename(seed)} ({cov} edges)")

        self.baseline_coverage = results[-1][0]
        self.best_coverage     = results[0][0]
        # Seed labeled pool with warmup results
        for cov, emb, seed in results:
            self.labeled_pool.append((cov, emb, seed, hashlib.sha256(open(seed,'rb').read()).hexdigest()[:16]))
        print(f"[+] Warmup done. best_cov={self.best_coverage} baseline={self.baseline_coverage}\n")
    
    def _score_all(self, embeddings: np.ndarray) -> np.ndarray:
        if self.acquisition.good_center is None:
            return np.random.rand(len(embeddings))
        dist_good = np.linalg.norm(embeddings - self.acquisition.good_center, axis=1)
        dist_rest = np.linalg.norm(embeddings - self.acquisition.rest_center, axis=1) \
                    if self.acquisition.rest_center is not None \
                    else np.ones(len(embeddings))
        return dist_rest - dist_good

    def run_iteration(self):
        self.iteration += 1
        # Always mutate from GOOD pool - top sqrt(N) inputs by coverage
        if self.labeled_pool:
            n         = len(self.labeled_pool)
            good_size = max(1, int(np.sqrt(n)))
            good_inputs = self.labeled_pool[:good_size]
            # Pick randomly from GOOD pool
            _, _, seed, _ = good_inputs[np.random.randint(0, len(good_inputs))]
        else:
            seed = self.seeds[self.iteration % len(self.seeds)]
        seed_hash = hashlib.sha256(open(seed, 'rb').read()).hexdigest()[:16]
        self.mutation_counts[seed_hash] = self.mutation_counts.get(seed_hash, 0) + 1

        # Policy 2: evict stale seed
        if self.mutation_counts[seed_hash] > Config.MAX_MUTATIONS_PER_SEED:
            self.labeled_pool = [x for x in self.labeled_pool if x[3] != seed_hash]
            print(f"  [evict-stale] {seed_hash} evicted after {Config.MAX_MUTATIONS_PER_SEED} mutations")
        
        mut_dir = os.path.join(self.queue_dir, f"iter_{self.iteration}")
        elapsed = int(time.time() - self.start_time)
        print(f"\n[Iter {self.iteration} | {elapsed}s] seed={os.path.basename(seed)}")

        print(f"  Mutating ({Config.MUTATIONS_PER_SEED})...")
        mutations = self.mutator.mutate_seed(seed, mut_dir, Config.MUTATIONS_PER_SEED)

        print(f"  Embedding...")
        embeddings = []
        for i in range(0, len(mutations), Config.BATCH_SIZE):
            batch      = mutations[i:i + Config.BATCH_SIZE]
            batch_data = [open(m, 'rb').read() for m in batch]
            embeddings.append(self.encoder.encode_batch(batch_data))
            print(f"    {min(i + Config.BATCH_SIZE, len(mutations))}/{len(mutations)}")
        embeddings = np.vstack(embeddings)

        # Score all and pick top 10
        scores     = self._score_all(embeddings)
        top10_idx  = np.argsort(scores)[-10:][::-1]
        print(f"  Executing top 10 mutations...")

        best_coverage_iter = 0
        best_idx           = top10_idx[0]
        best_embedding     = embeddings[best_idx]
        reached_all        = frozenset()
        triggered_all      = frozenset()

        for idx in top10_idx:
            inp        = mutations[idx]
            inp_bytes  = open(inp, 'rb').read()
            cov, crashed, reached, triggered = self.magma.run(inp)
            self.stats['executions'] += 1

            # Accumulate bug info
            reached_all   = reached_all | reached
            triggered_all = triggered_all | triggered

            if crashed:
                self.stats['crashes'] += 1
                h2 = hashlib.sha256(inp_bytes).hexdigest()[:16]
                shutil.copy(inp, os.path.join(self.crash_dir,
                            f"crash_{self.stats['crashes']:04d}_{h2}"))
                print(f"  [!!!] CRASH #{self.stats['crashes']}")

            if cov and cov > best_coverage_iter:
                best_coverage_iter = cov
                best_idx           = idx
                best_embedding     = embeddings[idx]

        # Calculate hash and prepare best input BEFORE using it
        best_input = mutations[best_idx]
        best_input_bytes = open(best_input, 'rb').read()
        h = hashlib.sha256(best_input_bytes).hexdigest()[:16]
        
        # Get final coverage of best input
        coverage, crashed, reached, triggered = self.magma.run(best_input)
        self.stats['executions'] += 1
        
        # Accumulate final bug info
        reached_all   = reached_all | reached
        triggered_all = triggered_all | triggered

        # Save best input permanently before mut_dir gets deleted
        perm_path = os.path.join(self.work_dir, "best_inputs", f"iter_{self.iteration}_{h}")
        os.makedirs(os.path.dirname(perm_path), exist_ok=True)
        shutil.copy(best_input, perm_path)
        best_input = perm_path

        # Bug tracking - passive observation only
        elapsed_f = time.time() - self.start_time
        self.bug_tracker.update(reached_all, triggered_all, best_input_bytes, elapsed_f)

        # Crash handling
        if crashed or coverage == -1:
            self.stats['crashes'] += 1
            crash_path = os.path.join(self.crash_dir, f"crash_{self.stats['crashes']:04d}_{h}")
            shutil.copy(best_input, crash_path)
            print(f"  [!!!] CRASH #{self.stats['crashes']} saved -> {crash_path}")

        # Coverage labeling
        if coverage is None:
            print("  [T] Timeout - skipping")
            shutil.rmtree(mut_dir, ignore_errors=True)
            return
        if coverage == -1:
            coverage = 0

        if coverage > self.best_coverage:
            self.best_coverage = coverage
            print(f"  [!!!] NEW BEST: {coverage} edges")

        # Add to combined pool with coverage score
        self.labeled_pool.append((coverage, best_embedding.tolist(), best_input, h))

        # Sort by coverage descending
        self.labeled_pool.sort(key=lambda x: x[0], reverse=True)

        n         = len(self.labeled_pool)
        good_size = max(1, int(np.sqrt(n)))

        # Rebuild centers
        self.acquisition.good_embeddings = []
        self.acquisition.rest_embeddings = []
        for cov, emb, path, fh in self.labeled_pool[:good_size]:
            self.acquisition.add_good(np.array(emb))
        for cov, emb, path, fh in self.labeled_pool[good_size:]:
            self.acquisition.add_rest(np.array(emb))

        # Policy 1: evict lowest coverage if pool too large
        if len(self.labeled_pool) > Config.MAX_POOL_SIZE:
            self.labeled_pool = self.labeled_pool[:Config.MAX_POOL_SIZE]
            n         = len(self.labeled_pool)
            good_size = max(1, int(np.sqrt(n)))
            print(f"  [evict-size] Pool capped at {Config.MAX_POOL_SIZE}")
        
        self.stats['good_inputs'] = good_size
        self.stats['rest_inputs'] = n - good_size

        # Find current input position by hash string comparison
        current_idx = good_size  # default REST
        for i, (cov, emb, path, fh) in enumerate(self.labeled_pool):
            if fh == h:
                current_idx = i
                break
        current_label = "GOOD" if current_idx < good_size else "REST"

        print(f"  -> {current_label} | "
            f"coverage={coverage} best={self.best_coverage} "
            f"GOOD pool={good_size} REST pool={n - good_size} "
            f"(sqrt({n})={good_size})")

        # Add to seeds if in good pool
        if current_label == "GOOD":
            dst = os.path.join(self.good_dir, f"good_{self.iteration}_{h}")
            shutil.copy(best_input, dst)
            if dst not in self.seeds:
                self.seeds.append(dst)
        else:
            dst = os.path.join(self.rest_dir, f"rest_{self.iteration}_{h}")
            shutil.copy(best_input, dst)

        self.stats['iterations'] = self.iteration
        shutil.rmtree(mut_dir, ignore_errors=True)

    def _debug_bug_seeds(self):
        """Show which pool the bug-reaching inputs ended up in."""
        if not self.bug_tracker.reach_history:
            return
        
        n         = len(self.labeled_pool)
        good_size = max(1, int(np.sqrt(n)))
        good_hashes = {x[3] for x in self.labeled_pool[:good_size]}
        rest_hashes = {x[3] for x in self.labeled_pool[good_size:]}

        print(f"\n  [BUG SEED DEBUG]")
        for entry in self.bug_tracker.reach_history:
            h   = entry['input_hash']
            bug = entry['bug']
            if h in good_hashes:
                loc = "GOOD"
            elif h in rest_hashes:
                loc = "REST"
            else:
                loc = "EVICTED"
            print(f"    {bug} -> input={h} in {loc} pool")

    def _print_stats(self, elapsed, remaining):
        bt = self.bug_tracker
        print(f"\n  {'='*66}")
        print(f"  STATS | elapsed={elapsed}s remaining={remaining}s")
        print(f"  {'─'*66}")
        print(f"  Iterations   : {self.stats['iterations']}")
        print(f"  Executions   : {self.stats['executions']}")
        print(f"  Best cov     : {self.best_coverage} edges")
        print(f"  Good inputs  : {self.stats['good_inputs']}")
        print(f"  Rest inputs  : {self.stats['rest_inputs']}")
        print(f"  Crashes      : {self.stats['crashes']}")
        print(f"  {'─'*66}")
        print(f"  Bugs reached : {len(bt.bugs_reached)}  {sorted(bt.bugs_reached)}")
        print(f"  Bugs trigg.  : {len(bt.bugs_triggered)}  {sorted(bt.bugs_triggered)}")
        print(f"  New cov evts : {bt.new_cov_events}")
        if bt.trigger_history:
            print(f"  Trigger log  :")
            for t in bt.trigger_history:
                print(f"    [{t['time']:.0f}s] {t['bug']}  input={t['input_hash']}")
        print(f"  {'='*66}\n")
        self._debug_bug_seeds()

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
            'fuzzer': 'ezr_magma',
            'target': self.magma.target_name,
            'elapsed_s': int(time.time() - self.start_time),
            **self.stats,
            **self.bug_tracker.summary(),
            'best_coverage': self.best_coverage,
            'baseline_coverage': self.baseline_coverage,
        }
        path = os.path.join(self.work_dir, "ezr_report.json")
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)

    def _print_final(self):
        bt = self.bug_tracker
        print(f"\n{'='*70}")
        print("Campaign complete!")
        print(f"{'='*70}")
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
        print(f"{'='*70}")

# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="EZR Fuzzer with Magma")
    parser.add_argument('--target', required=True,
                        choices=list(MagmaTarget.TARGETS.keys()),
                        help="Magma target to fuzz")
    parser.add_argument('--duration', type=int, default=3600,
                        help="Campaign duration in seconds")
    args = parser.parse_args()

    fuzzer = EZRMagmaFuzzer(args.target)
    fuzzer.run(args.duration)

if __name__ == "__main__":
    main()