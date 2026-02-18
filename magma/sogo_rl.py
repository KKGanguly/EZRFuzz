#!/usr/bin/env python3
"""
sogo_rl.py : SOGO-RL Fuzzer — fixed actLearn integration

KEY FIXES:
  1. Corpus is CAPPED at cfg.Stop*4 — actLearn sees ALL of it, not 0.1%
  2. Coverage tracking: new reached-set combination = interesting regardless
  3. After trigger: explicitly boost exploration of UNTRIGGERED reached bugs
  4. actLearn Stop tuned to corpus size so it's always meaningful
"""

import re, sys, os, math, time, random, hashlib, subprocess, signal
import tempfile, shutil, argparse, json
from pathlib import Path

BIG = 1E32

# ── actLearn (bl.py inline) ───────────────────────────────────────────────────

class o:
    __init__ = lambda i,**d: i.__dict__.update(**d)
    __repr__ = lambda i: i.__class__.__name__+str(i.__dict__)

def Num(txt=" ", at=0):
    return o(it=Num,txt=txt,at=at,n=0,mu=0,sd=0,m2=0,hi=-BIG,lo=BIG,rank=0,
             goal=0 if str(txt)[-1]=="-" else 1)

def Sym(txt=" ", at=0):
    return o(it=Sym,txt=txt,at=at,n=0,has={})

def Cols(names):
    cols = o(it=Cols,x=[],y=[],all=[],names=names)
    for n,s in enumerate(names):
        col = (Num if s[0].isupper() else Sym)(s,n)
        cols.all.append(col)
        if s[-1] != "X":
            (cols.y if s[-1] in "+-!" else cols.x).append(col)
    return cols

def Data(src=[]):
    return _adds(src, o(it=Data,n=0,rows=[],cols=None))

def clone(data, src=[]):
    d = Data([data.cols.names])
    for row in src: _add(row, d)
    return d

def _adds(src, i=None):
    for x in src:
        i = i or (Num() if isinstance(x,(int,float)) else Sym())
        _add(x, i)
    return i

def _sub(v,i,n=1): return _add(v,i,n=n,flip=-1)

def _add(v,i,n=1,flip=1):
    def _sym(): i.has[v]=flip*n+i.has.get(v,0)
    def _data():
        if not i.cols: i.cols=Cols(v)
        elif flip<0: [_sub(v[c.at],c,n) for c in i.cols.all]
        else: i.rows.append([_add(v[c.at],c,n) for c in i.cols.all])
    def _num():
        i.lo=min(v,i.lo); i.hi=max(v,i.hi)
        if flip<0 and i.n<2: i.mu=i.sd=0
        else:
            d=v-i.mu; i.mu+=flip*(d/i.n); i.m2+=flip*(d*(v-i.mu))
            i.sd=0 if i.n<=2 else (max(0,i.m2)/(i.n-1))**.5
    if v!="?":
        i.n+=flip*n
        _sym() if i.it is Sym else (_num() if i.it is Num else _data())
    return v

def _norm(v,col):
    if v=="?" or col.it is Sym: return v
    return (v-col.lo)/(col.hi-col.lo+1/BIG)

def _ydist(row,data,p=2):
    return (sum(abs(_norm(row[c.at],c)-c.goal)**p for c in data.cols.y)
            /len(data.cols.y))**(1/p)

def _ydists(rows,data): return sorted(rows,key=lambda r:_ydist(r,data))

def _like(row,data,nall=100,nh=2,k=1,m=2):
    def _col(v,col):
        if col.it is Sym:
            return (col.has.get(v,0)+m*(data.n+k)/(nall+k*nh))/(col.n+m+1/BIG)
        sd=col.sd+1/BIG
        return max(0,min(1,math.exp(-(v-col.mu)**2/(2*sd*sd))
                         /((2*math.pi*sd*sd)**.5)))
    prior=(data.n+k)/(nall+k*nh)
    tmp=[_col(row[x.at],x) for x in data.cols.x if row[x.at]!="?"]
    return sum(math.log(n) for n in tmp+[prior] if n>0)

def actLearn(data, cfg, shuffle=True):
    def _acquire(p,b,r):
        b,r = math.e**b, math.e**r
        q = 0 if cfg.acq=="xploit" else (1 if cfg.acq=="xplore" else 1-p)
        return (b+r*q)/abs(b*q-r+1/BIG)
    def _guess(row):
        return _acquire(n/cfg.Stop, _like(row,best,n,2), _like(row,rest,n,2))

    if shuffle: random.shuffle(data.rows)
    n    = cfg.start
    todo = data.rows[n:]
    done = _ydists(data.rows[:n], data)
    cut  = round(n**cfg.guess)
    best = clone(data, done[:cut])
    rest = clone(data, done[cut:])
    while len(todo)>2 and n<cfg.Stop:
        n+=1
        hi,*lo = sorted(todo[:cfg.Few*2], key=_guess, reverse=True)
        todo = lo[:cfg.Few]+todo[cfg.Few*2:]+lo[cfg.Few:]
        _add(hi,best); _add(hi,data)
        best.rows = _ydists(best.rows,data)
        if len(best.rows)>=round(n**cfg.guess):
            _add(_sub(best.rows.pop(-1),best),rest)
    return o(best=best,rest=rest,todo=todo)

# ── Magma monitor ─────────────────────────────────────────────────────────────

MONITOR = "/magma_out/monitor"

def run_target(binary, input_bytes, timeout_ms, tmpdir):
    infile = os.path.join(tmpdir,"cur_input")
    with open(infile,"wb") as f: f.write(input_bytes)

    cmd = binary if isinstance(binary,list) else binary.split()
    cmd = [c if c!="@@" else infile for c in cmd]
    if "@@" not in " ".join(binary if isinstance(binary,list) else [binary]):
        cmd = cmd + [infile]

    use_mon = os.path.exists(MONITOR)
    full    = ([MONITOR,"--fetch","watch","--dump","human"]+cmd if use_mon else cmd)

    t0 = time.perf_counter()
    reached, triggered = set(), set()
    crashed = hung = False

    try:
        proc = subprocess.Popen(full, cwd=tmpdir,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            out,err = proc.communicate(timeout=timeout_ms/1000)
        except subprocess.TimeoutExpired:
            proc.kill(); out,err=proc.communicate()
            return False,True,frozenset(),frozenset(),(time.perf_counter()-t0)*1000

        elapsed=(time.perf_counter()-t0)*1000
        rc=proc.returncode; sig=-rc if rc<0 else 0
        crashed=sig<0 and sig!=-(signal.SIGALRM)

        if use_mon:
            for line in out.decode("utf-8","replace").splitlines():
                m=re.match('([^ ]+) reached ([0-9]+) triggered ([0-9]+)',line)
                if m:
                    bid,r,t=m.group(1),int(m.group(2)),int(m.group(3))
                    if r>0: reached.add(bid)
                    if t>0: triggered.add(bid)
            if triggered: crashed=True

    except FileNotFoundError:
        return False,False,frozenset(),frozenset(),0.0

    return crashed,hung,frozenset(reached),frozenset(triggered),elapsed

# ── Mutation ──────────────────────────────────────────────────────────────────

MAGIC=[0,1,127,128,255,0xFFFF,0x8000,0x7FFF,0xFFFFFFFF]

def mutate(data:bytes, n:int=8)->bytes:
    buf=bytearray(data) if data else bytearray(b"\x00")
    for _ in range(random.randint(1,n)):
        if not buf: buf=bytearray(b"\x00")
        pos=random.randint(0,len(buf)-1)
        op=random.randint(0,9)
        if   op==0: buf[pos]^=1<<random.randint(0,7)
        elif op==1: buf[pos]=random.choice(MAGIC)&0xFF
        elif op==2: buf[pos]=random.randint(0,255)
        elif op==3: del buf[pos]
        elif op==4: buf.insert(pos,random.randint(0,255))
        elif op==5: del buf[pos:pos+random.randint(1,32)]
        elif op==6: buf[pos:pos]=buf[pos:pos+random.randint(1,16)]
        elif op==7:
            for i in range(pos,min(pos+random.randint(1,16),len(buf))):
                buf[i]=random.randint(0,255)
        elif op==8: buf[pos]=(buf[pos]+random.randint(-35,35))&0xFF
        elif op==9:
            l=random.randint(1,max(1,min(8,len(buf)//2)))
            p2=random.randint(0,len(buf)-1)
            buf[pos:pos]=buf[p2:p2+l]
    return bytes(buf)

# ── Corpus — CAPPED so actLearn always sees 100% of it ───────────────────────

NAMES = [
    "BugCount+",    # distinct bugs reached (normalized)
    "TrigCount+",   # bugs triggered (normalized)
    "CrashProx+",   # Jaccard sim to nearest trigger's reached set
    "CovNovel+",    # 1 if this input reached any NEW bug not seen before
    "TimeScore-",   # exec time (lower=better)
    "SizeScore-",   # input size (smaller=better)
    "MutDepth+",    # mutation depth from seed
]

MAX_BUGS=10.0; MAX_TIME=2000.0; MAX_SIZE=65536.0; MAX_DEPTH=20.0

class Corpus:
    def __init__(self, seed_dir, cfg):
        self.cfg             = cfg
        # CAPPED corpus: max = cfg.Stop * 4
        # When full, evict the worst-scoring input (highest ydist)
        self.cap             = cfg.Stop * 4
        self.inputs          = []
        self.reached_sets    = []
        self.depths          = []
        self.rows            = []        # feature rows, parallel to inputs
        self.seen_bug_combos = set()     # frozensets of reached bugs
        self.seen_bugs       = set()     # individual bugs ever reached
        self.trigger_reached = []        # reached sets from triggers
        self.data            = Data([NAMES])
        self.stats           = o(execs=0,crashes=0,hangs=0,
                                 bugs_reached=set(),bugs_triggered=set(),
                                 new_cov_events=0, start=time.time())
        self._load(seed_dir)

    def _load(self, seed_dir):
        p=Path(seed_dir)
        files=sorted(f for f in p.iterdir() if f.is_file()) if p.exists() else []
        if not files:
            self.inputs.append(b"\x00"); self.reached_sets.append(frozenset())
            self.depths.append(0); self.rows.append(None)
            print("[!] No seeds, using empty input"); return
        for f in files:
            self.inputs.append(f.read_bytes())
            self.reached_sets.append(frozenset())
            self.depths.append(0)
            self.rows.append(None)
        print(f"[*] Loaded {len(self.inputs)} seeds from {seed_dir}")

    def _crash_prox(self, reached):
        if not self.trigger_reached or not reached: return 0.0
        return max(len(reached&tr)/max(1,len(reached|tr))
                   for tr in self.trigger_reached)

    def _make_row(self, reached, triggered, elapsed_ms, size, depth, cov_novel):
        return [
            min(1.0, len(reached)   / MAX_BUGS),
            min(1.0, len(triggered) / MAX_BUGS),
            self._crash_prox(reached),
            1.0 if cov_novel else 0.0,
            min(1.0, elapsed_ms / MAX_TIME),
            min(1.0, size       / MAX_SIZE),
            min(1.0, depth      / MAX_DEPTH),
        ]

    def _evict_worst(self):
        n = min(len(self.data.rows), len(self.inputs))
        if n < 2: return
        worst_idx = max(range(n), key=lambda i: _ydist(self.data.rows[i], self.data))
        self.inputs.pop(worst_idx)
        self.reached_sets.pop(worst_idx)
        self.depths.pop(worst_idx)
        self.rows.pop(worst_idx)
        row = self.data.rows[worst_idx]
        self.data.rows.pop(worst_idx)
        _sub(row, self.data)

    def record(self, inp, crashed, hung, reached, triggered, elapsed_ms, depth):
        s = self.stats
        s.execs += 1

        # New coverage = reached a bug combination OR individual bug never seen
        new_bugs  = reached - s.bugs_reached
        size_bucket = len(inp) // 64
        edge_key    = (frozenset(reached), size_bucket)
        cov_novel   = edge_key not in self.seen_bug_combos

        # Print events
        if new_bugs:
            s.new_cov_events += 1
            print(f"  [NEW COV]   {sorted(new_bugs)}  (new bugs reached)")
        new_t = triggered - s.bugs_triggered
        if new_t:
            print(f"  [TRIGGERED] {sorted(new_t)}  <== BUG FOUND!")
            self.trigger_reached.append(reached)

        s.bugs_reached   |= reached
        s.bugs_triggered |= triggered
        self.seen_bug_combos.add(edge_key)
        if crashed: s.crashes += 1
        if hung:    s.hangs   += 1

        row = self._make_row(reached, triggered, elapsed_ms, len(inp), depth, cov_novel)

        # Evict worst if corpus full
        if len(self.inputs) >= self.cap:
            self._evict_worst()

        self.inputs.append(inp)
        self.reached_sets.append(reached)
        self.depths.append(depth)
        self.rows.append(row)
        _add(row, self.data)
        return row, cov_novel

    def select_seed(self):
        """
        actLearn selects from the ENTIRE capped corpus.
        Because corpus size <= Stop*4, actLearn evaluates every input.
        
        After triggers: actLearn's CrashProx+ naturally exploits similar inputs.
        CovNovel+ ensures exploration toward untriggered bugs continues.
        The adapt acquisition balances both automatically.
        """
        if self.data.n < self.cfg.start + 2:
            candidates = [(inp,d) for inp,rs,d
                          in zip(self.inputs,self.reached_sets,self.depths) if rs]
            if candidates: return random.choice(candidates)
            return random.choice(self.inputs), 0

        result = actLearn(self.data, self.cfg, shuffle=True)

        best_inputs = []
        for row in result.best.rows:
            try:
                idx = self.data.rows.index(row)
                if idx < len(self.inputs):
                    best_inputs.append((self.inputs[idx], self.depths[idx]))
            except ValueError:
                pass

        if not best_inputs:
            return random.choice(self.inputs), 0

        return random.choice(best_inputs)

# ── Main fuzz loop ────────────────────────────────────────────────────────────

def fuzz(cfg):
    os.makedirs(cfg.output, exist_ok=True)
    crash_dir=Path(cfg.output,"crashes"); crash_dir.mkdir(exist_ok=True)
    queue_dir=Path(cfg.output,"queue");   queue_dir.mkdir(exist_ok=True)
    tmpdir=tempfile.mkdtemp(prefix="sogorl_")
    corpus=Corpus(cfg.input, cfg)

    mon_ok=os.path.exists(MONITOR)
    print("="*60)
    print("  SOGO-RL : actLearn-driven semantic fuzzer")
    print(f"  Target  : {cfg.target}")
    print(f"  Monitor : {'YES - rich bug signal' if mon_ok else 'NO - exit-code fallback'}")
    print(f"  Corpus cap : {corpus.cap} inputs (actLearn sees 100%)")
    print(f"  acq={cfg.acq}  Stop={cfg.Stop}  budget={cfg.maxtime}s")
    print("="*60)

    start=time.time(); last_report=start; last_al=start
    seed,depth=corpus.inputs[0],0

    try:
        while time.time()-start < cfg.maxtime:
            elapsed=time.time()-start

            # actLearn re-selects seed every 20s (10s after trigger)
            interval = 10 if corpus.trigger_reached else 20
            if time.time()-last_al > interval:
                seed,depth = corpus.select_seed()
                last_al = time.time()

            inp   = mutate(seed, cfg.maxmut)
            depth = depth + 1

            crashed,hung,reached,triggered,elapsed_ms = \
                run_target(cfg.target, inp, cfg.timeout, tmpdir)

            row,novel = corpus.record(inp,crashed,hung,reached,
                                      triggered,elapsed_ms,depth)

            if novel:
                print(f"  [NEW BUCKET] bugs={len(reached)} trig={len(triggered)} "
                      f"prox={row[2]:.2f} depth={depth}")

            if crashed:
                fname=f"crash_{corpus.stats.crashes:05d}.bin"
                (crash_dir/fname).write_bytes(inp)
                # Immediately re-select seed to exploit crash neighborhood
                seed,depth = corpus.select_seed()
                last_al = time.time()

            if time.time()-last_report >= 10:
                s=corpus.stats; rate=s.execs/max(1,time.time()-start)
                print(f"[{elapsed:6.0f}s] "
                      f"execs={s.execs:>8,} exec/s={rate:5.0f} "
                      f"crashes={s.crashes:>3} "
                      f"corpus={len(corpus.inputs):>4}/{corpus.cap} "
                      f"reached={len(s.bugs_reached):>2} "
                      f"triggered={len(s.bugs_triggered):>2} "
                      f"new_cov={s.new_cov_events:>3}")
                last_report=time.time()

    except KeyboardInterrupt:
        print("\n[!] Stopped.")
    finally:
        shutil.rmtree(tmpdir,ignore_errors=True)

    s=corpus.stats; elapsed=time.time()-start
    report=dict(fuzzer="sogo_rl",target=cfg.target,
                elapsed_s=round(elapsed,1),
                total_execs=s.execs,
                exec_per_s=round(s.execs/max(1,elapsed),1),
                unique_crashes=s.crashes,
                bugs_reached=sorted(s.bugs_reached),
                bugs_triggered=sorted(s.bugs_triggered),
                n_reached=len(s.bugs_reached),
                n_triggered=len(s.bugs_triggered))
    Path(cfg.output,"sogo_rl_report.json").write_text(json.dumps(report,indent=2))
    print("\n[+] Final:"); print(json.dumps(report,indent=2))
    return report

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("-t","--target",  default="./target")
    p.add_argument("-i","--input",   default="./seeds")
    p.add_argument("-o","--output",  default="./output")
    p.add_argument("-T","--timeout", type=int,   default=1000)
    p.add_argument("-S","--Stop",    type=int,   default=64)
    p.add_argument("-s","--start",   type=int,   default=4)
    p.add_argument("-a","--acq",                 default="adapt")
    p.add_argument("-g","--guess",   type=float, default=0.5)
    p.add_argument("-F","--Few",     type=int,   default=50)
    p.add_argument("-r","--rseed",   type=int,   default=1234567891)
    p.add_argument("-M","--maxtime", type=int,   default=3600)
    p.add_argument("-X","--maxmut",  type=int,   default=8)
    return p.parse_args()

if __name__=="__main__":
    args=parse_args()
    random.seed(args.rseed)
    fuzz(args)
