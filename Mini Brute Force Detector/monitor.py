#!/usr/bin/env python3
import argparse, re, csv, sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

MONTHS = {m:i for i,m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}
IP_RE = re.compile(r'(?:(?:from|rhost=)\s*)(\d+\.\d+\.\d+\.\d+)')

def parse_linux_line(line, assume_year=None):
    parts = line.split()
    if len(parts) < 3: return None, None
    mon, day, time_ = parts[0], parts[1], parts[2]
    if mon not in MONTHS: return None, None
    if assume_year is None:
        assume_year = datetime.now().year
    try:
        ts = datetime.strptime(f"{assume_year} {MONTHS[mon]} {day} {time_}", "%Y %m %d %H:%M:%S")
    except Exception:
        return None, None
    ip = None
    m = IP_RE.search(line)
    if m: ip = m.group(1)
    return ts, ip

def parse_win_csv_row(row):
    msg = row.get("Message","") or row.get("message","")
    ip = None
    m = re.search(r"Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)", msg)
    if m:
        ip = m.group(1)
    time_raw = row.get("TimeCreated","") or row.get("timecreated","")
    ts = None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
        try:
            ts = datetime.strptime(time_raw.replace("T"," ").split("Z")[0], fmt)
            break
        except Exception:
            continue
    return ts, ip

def alert(text):
    print(text)
    with open("alerts.txt","a", encoding="utf-8") as f:
        f.write(text + "\n")

def detect(stream_iter, parse_fn, window_sec=60, threshold=3, label=""):
    buckets = defaultdict(lambda: deque())
    window = timedelta(seconds=window_sec)

    for item in stream_iter:
        ts, key = parse_fn(item)
        if ts is None:
            continue
        if key is None:
            key = "unknown"
        dq = buckets[key]
        dq.append(ts)
        while dq and (ts - dq[0]) > window:
            dq.popleft()
        if len(dq) >= threshold:
            alert(f"[ALERT] {label} possible brute force: key={key} count={len(dq)} window={window_sec}s at {ts.isoformat()}")

def run_linux(path, **kw):
    with open(path, "r", errors="ignore") as f:
        lines = (line for line in f if "Failed password" in line)
        detect(lines, lambda ln: parse_linux_line(ln), label="LINUX", **kw)

def run_windows(csv_path, **kw):
    with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        rows = []
        for r in reader:
            if r.get("Id","") in ("4625", 4625):
                rows.append(r)
            elif "4625" in (r.get("EventID","") or ""):
                rows.append(r)
        detect(rows, parse_win_csv_row, label="WINDOWS", **kw)

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Mini brute-force detector (3+ fails in 60s).")
    p.add_argument("--mode", choices=["linux","windows"], required=True)
    p.add_argument("--path", required=True, help="Path to log file (linux auth.log or windows CSV).")
    p.add_argument("--threshold", type=int, default=3)
    p.add_argument("--window", type=int, default=60, help="Seconds")
    args = p.parse_args()

    if args.mode == "linux":
        run_linux(args.path, threshold=args.threshold, window_sec=args.window)
    else:
        run_windows(args.path, threshold=args.threshold, window_sec=args.window)
