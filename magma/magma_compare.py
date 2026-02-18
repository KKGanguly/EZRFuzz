#!/usr/bin/env python3
"""
magma_compare.py : Compare SOGO-RL vs other fuzzers on Magma benchmark

This script:
  1. Runs selected fuzzers (SOGO-RL, AFL++, AFL, libFuzzer) on chosen Magma targets
  2. Parses each fuzzer's output to collect bugs reached/triggered, exec/s, crashes
  3. Produces a rich results table (console + CSV + HTML)

Magma layout assumed:
  $MAGMA_ROOT/
    targets/<target>/  (e.g. libpng, openssl, sqlite3 ...)
    fuzzers/<fuzzer>/  (e.g. afl, aflpp, libfuzzer, sogo_rl)
    campaigns/<run>/

Usage:
  python magma_compare.py [options]

OPTIONS:
  --magma       path to Magma root dir          = ./magma
  --targets     comma-sep list of targets       = libpng,sqlite3,openssl
  --fuzzers     comma-sep list of fuzzers       = sogo_rl,aflpp
  --time        fuzz time per campaign (s)      = 3600
  --reps        repetitions per config          = 3
  --workers     parallel campaigns              = 4
  --output      results output directory        = ./results
  --skip-run    just parse existing results     = False
  --sogo-script path to sogo_rl.py             = ./sogo_rl.py
"""

import argparse, os, sys, re, json, csv, time, subprocess, shutil
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
import statistics

# ── Fuzzer definitions ────────────────────────────────────────────────────────

FUZZER_CMDS = {
    # Each value is a callable: (target_bin, seeds, output, timeout_s) -> cmd list
    "sogo_rl": lambda tbin, seeds, out, t: [
        sys.executable, "./sogo_rl.py",
        "-t", tbin, "-i", seeds, "-o", out,
        "-M", str(t), "-a", "adapt"
    ],
    "aflpp": lambda tbin, seeds, out, t: [
        "afl-fuzz",
        "-i", seeds, "-o", out,
        "-V", str(t),           # timeout in seconds (afl++ supports -V)
        "--", tbin, "@@"
    ],
    "afl": lambda tbin, seeds, out, t: [
        "afl-fuzz",
        "-i", seeds, "-o", out,
        "--", tbin, "@@"
    ],
    "libfuzzer": lambda tbin, seeds, out, t: [
        tbin,
        f"-max_total_time={t}",
        f"-artifact_prefix={out}/",
        seeds
    ],
    "honggfuzz": lambda tbin, seeds, out, t: [
        "honggfuzz",
        "-i", seeds, "-o", out,
        "--run_time", str(t),
        "--", tbin, "___FILE___"
    ],
}

# Magma target → binary path template within Magma build
# Adjust these to match your Magma install's build outputs
TARGET_BINS = {
    "libpng":   "{magma}/targets/libpng/repo/build/pngtest",
    "sqlite3":  "{magma}/targets/sqlite3/repo/build/sqlite3_fuzz",
    "openssl":  "{magma}/targets/openssl/repo/build/server_fuzz",
    "libxml2":  "{magma}/targets/libxml2/repo/build/xmllint_fuzz",
    "php":      "{magma}/targets/php/repo/build/php_fuzz",
    "poppler":  "{magma}/targets/poppler/repo/build/pdf_fuzz",
    "lua":      "{magma}/targets/lua/repo/build/lua_fuzz",
}

TARGET_SEEDS = {
    k: "{magma}/targets/{k}/corpus/".format(magma="{magma}", k=k)
    for k in TARGET_BINS
}

# ── Magma bug oracle ──────────────────────────────────────────────────────────
# Magma patches targets with MAGMA_LOG and canary counters.
# When a bug is *reached*  → prints "MAGMA: bug <ID> reached"  to stderr
# When a bug is *triggered* → prints "MAGMA: bug <ID> triggered" to stderr

BUG_REACHED_RE  = re.compile(r"MAGMA:\s*bug\s+(\w+)\s+reached")
BUG_TRIGGER_RE  = re.compile(r"MAGMA:\s*bug\s+(\w+)\s+triggered")

def parse_magma_logs(output_dir):
    """
    Scan crash/hang/queue stderr files for Magma bug oracle messages.
    Returns dict: {bug_id: {"reached": bool, "triggered": bool}}
    """
    bugs = {}
    out = Path(output_dir)
    for f in out.rglob("*.stderr"):
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        for m in BUG_REACHED_RE.finditer(text):
            bid = m.group(1)
            bugs.setdefault(bid, {"reached": False, "triggered": False})
            bugs[bid]["reached"] = True
        for m in BUG_TRIGGER_RE.finditer(text):
            bid = m.group(1)
            bugs.setdefault(bid, {"reached": False, "triggered": False})
            bugs[bid]["triggered"] = True
    return bugs

# Also parse AFL's fuzzer_stats for exec/s
def parse_afl_stats(output_dir):
    stats_file = Path(output_dir) / "default" / "fuzzer_stats"
    if not stats_file.exists():
        stats_file = Path(output_dir) / "fuzzer_stats"
    result = {}
    if stats_file.exists():
        for line in stats_file.read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
    return result

def parse_sogo_report(output_dir):
    report = Path(output_dir) / "sogo_rl_report.json"
    if report.exists():
        return json.loads(report.read_text())
    return {}

def parse_libfuzzer_log(output_dir):
    """libFuzzer writes stats to stdout captured in a log file."""
    logf = Path(output_dir) / "libfuzzer.log"
    result = {}
    if logf.exists():
        text = logf.read_text(errors="replace")
        m = re.search(r"stat::number_of_executed_units:\s*(\d+)", text)
        if m: result["execs"] = int(m.group(1))
        m = re.search(r"CRASH", text)
        if m: result["crashes"] = 1
    return result

# ── Campaign runner ───────────────────────────────────────────────────────────

def run_campaign(fuzzer, target, magma_root, fuzz_time, output_dir, rep):
    """Run one (fuzzer, target, rep) campaign. Returns result dict."""
    target_bin_tmpl = TARGET_BINS.get(target)
    if not target_bin_tmpl:
        return {"error": f"Unknown target {target}"}

    target_bin = target_bin_tmpl.format(magma=magma_root)
    seeds      = TARGET_SEEDS.get(target, "").format(magma=magma_root)
    out_path   = str(Path(output_dir) / fuzzer / target / f"rep{rep:02d}")
    os.makedirs(out_path, exist_ok=True)

    if not Path(target_bin).exists():
        return {
            "fuzzer": fuzzer, "target": target, "rep": rep,
            "error": f"Binary not found: {target_bin}. "
                     "Did you build Magma targets?"
        }

    if fuzzer not in FUZZER_CMDS:
        return {"fuzzer": fuzzer, "target": target, "rep": rep,
                "error": f"Unknown fuzzer {fuzzer}"}

    cmd = FUZZER_CMDS[fuzzer](target_bin, seeds, out_path, fuzz_time)
    print(f"  [+] Starting: {fuzzer}/{target}/rep{rep} "
          f"(pid will appear) cmd: {' '.join(cmd[:5])}...")

    t0 = time.time()
    log_path = Path(out_path) / "campaign.log"
    try:
        with open(log_path, "w") as logf:
            proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT,
                                    env={**os.environ,
                                         "AFL_NO_UI": "1",
                                         "AFL_AUTORESUME": "1"})
            proc.wait(timeout=fuzz_time + 120)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait()
    except FileNotFoundError as e:
        return {"fuzzer": fuzzer, "target": target, "rep": rep,
                "error": str(e)}
    elapsed = time.time() - t0

    # ── Parse results ──────────────────────────────────────────────────────
    bugs = parse_magma_logs(out_path)
    n_reached  = sum(1 for b in bugs.values() if b["reached"])
    n_triggered= sum(1 for b in bugs.values() if b["triggered"])

    exec_per_s = 0
    crashes    = 0

    if fuzzer == "sogo_rl":
        rep_data = parse_sogo_report(out_path)
        exec_per_s = rep_data.get("exec_per_s", 0)
        crashes    = rep_data.get("unique_crashes", 0)
    elif fuzzer in ("afl","aflpp"):
        afl_data = parse_afl_stats(out_path)
        try: exec_per_s = float(afl_data.get("execs_per_sec","0"))
        except: pass
        try: crashes = int(afl_data.get("unique_crashes","0"))
        except: pass
    elif fuzzer == "libfuzzer":
        lf_data = parse_libfuzzer_log(out_path)
        exec_per_s = lf_data.get("execs",0)/max(1,elapsed)
        crashes    = lf_data.get("crashes",0)

    return {
        "fuzzer":     fuzzer,
        "target":     target,
        "rep":        rep,
        "elapsed_s":  round(elapsed,1),
        "exec_per_s": round(exec_per_s,1),
        "unique_crashes": crashes,
        "bugs_reached":   n_reached,
        "bugs_triggered": n_triggered,
        "bug_ids_reached":   sorted(b for b,v in bugs.items() if v["reached"]),
        "bug_ids_triggered": sorted(b for b,v in bugs.items() if v["triggered"]),
    }

# ── Aggregation & reporting ───────────────────────────────────────────────────

def aggregate(results):
    """
    Group by (fuzzer, target), compute mean ± SD over reps.
    Returns list of summary dicts.
    """
    from collections import defaultdict
    groups = defaultdict(list)
    for r in results:
        if "error" in r:
            print(f"  [!] Error in {r.get('fuzzer')}/{r.get('target')}/rep{r.get('rep')}: {r['error']}")
            continue
        groups[(r["fuzzer"], r["target"])].append(r)

    rows = []
    for (fuzzer, target), reps in sorted(groups.items()):
        def m(key): return statistics.mean(r[key] for r in reps)
        def sd(key):
            vals = [r[key] for r in reps]
            return statistics.stdev(vals) if len(vals)>1 else 0.0
        all_reached   = set(b for r in reps for b in r["bug_ids_reached"])
        all_triggered = set(b for r in reps for b in r["bug_ids_triggered"])
        rows.append({
            "fuzzer":        fuzzer,
            "target":        target,
            "reps":          len(reps),
            "exec/s (mean)": f"{m('exec_per_s'):.0f}",
            "exec/s (sd)":   f"{sd('exec_per_s'):.0f}",
            "crashes(mean)": f"{m('unique_crashes'):.1f}",
            "reached(mean)": f"{m('bugs_reached'):.1f}",
            "reached(sd)":   f"{sd('bugs_reached'):.1f}",
            "triggered(mean)":f"{m('bugs_triggered'):.1f}",
            "triggered(sd)":  f"{sd('bugs_triggered'):.1f}",
            "triggered/reached": (
                f"{m('bugs_triggered')/max(0.001,m('bugs_reached'))*100:.0f}%"
                if m('bugs_reached')>0 else "N/A"),
            "all_reached_bugs":   ",".join(sorted(all_reached)),
            "all_triggered_bugs": ",".join(sorted(all_triggered)),
        })
    return rows

def print_table(rows):
    if not rows:
        print("[!] No results to display.")
        return
    cols = ["fuzzer","target","reps","exec/s (mean)","crashes(mean)",
            "reached(mean)","triggered(mean)","triggered(sd)","triggered/reached"]
    widths = {c: max(len(c), max((len(str(r.get(c,""))) for r in rows), default=0))
              for c in cols}
    sep = "+" + "+".join("-"*(widths[c]+2) for c in cols) + "+"
    hdr = "|" + "|".join(f" {c:<{widths[c]}} " for c in cols) + "|"
    print("\n" + "="*len(sep))
    print("  MAGMA BENCHMARK RESULTS")
    print("="*len(sep))
    print(sep); print(hdr); print(sep)
    prev_fuzzer = None
    for r in rows:
        if prev_fuzzer and r["fuzzer"] != prev_fuzzer:
            print(sep)
        row_str = "|" + "|".join(f" {str(r.get(c,'')):<{widths[c]}} " for c in cols) + "|"
        print(row_str)
        prev_fuzzer = r["fuzzer"]
    print(sep)

def save_csv(rows, path):
    if not rows: return
    with open(path,"w",newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    print(f"[+] CSV saved: {path}")

def save_html(rows, path, fuzz_time, targets, fuzzers):
    if not rows:
        with open(path,"w") as f: f.write("<p>No results.</p>")
        return
    cols = ["fuzzer","target","reps","exec/s (mean)","exec/s (sd)",
            "crashes(mean)","reached(mean)","reached(sd)",
            "triggered(mean)","triggered(sd)","triggered/reached"]

    def cell_class(r, c):
        if c == "triggered/reached":
            try:
                pct = float(r[c].rstrip("%"))
                if pct >= 60: return "good"
                if pct >= 30: return "mid"
                return "bad"
            except: return ""
        if c == "triggered(mean)":
            try:
                v = float(r[c])
                if v >= 3: return "good"
                if v >= 1: return "mid"
                return "bad"
            except: return ""
        return ""

    thead = "".join(f"<th>{c}</th>" for c in cols)
    tbody = ""
    for r in rows:
        cells = "".join(
            f'<td class="{cell_class(r,c)}">{r.get(c,"")}</td>' for c in cols)
        tbody += f"<tr>{cells}</tr>\n"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>SOGO-RL vs Fuzzers — Magma Results</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background:#0f0f1a; color:#e0e0e0; padding:2em; }}
  h1   {{ color:#7ec8e3; }}
  .meta{{ color:#888; font-size:.9em; margin-bottom:1.5em; }}
  table{{ border-collapse:collapse; width:100%; font-size:.9em; }}
  th   {{ background:#1a1a2e; color:#7ec8e3; padding:10px 14px; text-align:left; border-bottom:2px solid #333; }}
  td   {{ padding:8px 14px; border-bottom:1px solid #222; }}
  tr:hover td {{ background:#1a1a2e; }}
  .good{{ background:#0d3320; color:#4caf50; font-weight:bold; }}
  .mid {{ background:#2d2800; color:#ffc107; }}
  .bad {{ background:#2d0a0a; color:#f44336; }}
  .note{{ margin-top:2em; color:#888; font-size:.85em; }}
</style>
</head><body>
<h1>🔬 SOGO-RL vs Fuzzers — Magma Benchmark Results</h1>
<div class="meta">
  Fuzz time: {fuzz_time}s per campaign &nbsp;|&nbsp;
  Targets: {', '.join(targets)} &nbsp;|&nbsp;
  Fuzzers: {', '.join(fuzzers)} &nbsp;|&nbsp;
  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>
<table>
<thead><tr>{thead}</tr></thead>
<tbody>{tbody}</tbody>
</table>
<div class="note">
  <b>triggered/reached</b>: fraction of reachable bugs actually triggered (higher = better semantic guidance).
  SOGO-RL uses stderr oracle signals + actLearn acquisition instead of coverage-only feedback.
</div>
</body></html>"""
    with open(path,"w") as f: f.write(html)
    print(f"[+] HTML saved: {path}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="SOGO-RL vs fuzzers on Magma")
    p.add_argument("--magma",       default="./magma",
                   help="Path to Magma root directory")
    p.add_argument("--targets",     default="libpng,sqlite3",
                   help="Comma-sep target list")
    p.add_argument("--fuzzers",     default="sogo_rl,aflpp",
                   help="Comma-sep fuzzer list: sogo_rl,afl,aflpp,libfuzzer,honggfuzz")
    p.add_argument("--time",        type=int, default=3600,
                   help="Fuzz time per campaign (seconds)")
    p.add_argument("--reps",        type=int, default=3,
                   help="Repetitions per (fuzzer,target)")
    p.add_argument("--workers",     type=int, default=4,
                   help="Parallel campaigns")
    p.add_argument("--output",      default="./magma_results",
                   help="Results output directory")
    p.add_argument("--skip-run",    action="store_true",
                   help="Skip fuzzing, just parse existing output dir")
    p.add_argument("--sogo-script", default="./sogo_rl.py",
                   help="Path to sogo_rl.py")
    return p.parse_args()

def main():
    args  = parse_args()
    targets = [t.strip() for t in args.targets.split(",")]
    fuzzers = [f.strip() for f in args.fuzzers.split(",")]
    os.makedirs(args.output, exist_ok=True)

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  Magma Benchmark Comparison Runner                           ║
║  Fuzzers : {', '.join(fuzzers):<50}║
║  Targets : {', '.join(targets):<50}║
║  Time    : {args.time}s × {args.reps} reps × {len(fuzzers)*len(targets)} configs          ║
╚══════════════════════════════════════════════════════════════╝
""")

    # Validate fuzzer availability
    for fz in fuzzers:
        if fz == "sogo_rl":
            if not Path(args.sogo_script).exists():
                print(f"[!] sogo_rl.py not found at {args.sogo_script}. "
                      "Will fail at runtime.")
        elif fz in ("afl","aflpp"):
            if not shutil.which("afl-fuzz"):
                print(f"[!] afl-fuzz not in PATH — {fz} campaigns will fail.")
        elif fz == "libfuzzer":
            print("[i] libFuzzer: ensure target binary is compiled with -fsanitize=fuzzer")
        elif fz == "honggfuzz":
            if not shutil.which("honggfuzz"):
                print("[!] honggfuzz not in PATH")

    # Check Magma root
    if not Path(args.magma).exists():
        print(f"[!] Magma root not found: {args.magma}")
        print("    Clone Magma: git clone https://github.com/google/magma")
        print("    Then build: cd magma && ./tools/captain/magma_build.sh")

    results = []

    if not args.skip_run:
        # Build campaign list
        campaigns = []
        for rep in range(1, args.reps+1):
            for fuzzer in fuzzers:
                for target in targets:
                    campaigns.append((fuzzer, target, args.magma,
                                      args.time, args.output, rep))

        print(f"[*] Launching {len(campaigns)} campaigns "
              f"({args.workers} parallel)...\n")

        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(run_campaign, *c): c for c in campaigns
            }
            for fut in as_completed(futures):
                c = futures[fut]
                try:
                    r = fut.result()
                    results.append(r)
                    status = (f"triggered={r.get('bugs_triggered','?')} "
                              f"reached={r.get('bugs_reached','?')}"
                              if "error" not in r else f"ERROR: {r['error']}")
                    print(f"  ✓ {c[0]}/{c[1]}/rep{c[5]} → {status}")
                except Exception as e:
                    print(f"  ✗ {c[0]}/{c[1]}/rep{c[5]} exception: {e}")
                    results.append({"fuzzer":c[0],"target":c[1],"rep":c[5],
                                    "error":str(e)})

        # Save raw results
        raw_path = Path(args.output) / "raw_results.json"
        with open(raw_path,"w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Raw results saved: {raw_path}")
    else:
        # Load existing
        raw_path = Path(args.output) / "raw_results.json"
        if raw_path.exists():
            results = json.loads(raw_path.read_text())
            print(f"[*] Loaded {len(results)} results from {raw_path}")
        else:
            print(f"[!] No raw_results.json in {args.output}")

    # ── Aggregate and report ───────────────────────────────────────────────
    summary = aggregate(results)
    print_table(summary)

    csv_path  = Path(args.output) / "summary.csv"
    html_path = Path(args.output) / "summary.html"
    save_csv(summary, csv_path)
    save_html(summary, html_path, args.time, targets, fuzzers)

    print(f"\n[+] All done. Results in {args.output}/")
    print(f"    Open {html_path} in a browser for the interactive table.")

if __name__ == "__main__":
    main()
