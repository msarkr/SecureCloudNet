FlowGuard – Sliding-Window Intrusion Pattern Detector (C++)

1. Overview
-----------
FlowGuard is a small C++ program that analyzes timestamped network logs
and detects three common intrusion patterns:

  • Port scanning (many distinct ports from one source to one destination)
  • Brute-force login attempts (many failed connections to one host:port)
  • Traffic spikes (sudden surge of connections to a single destination)

The log format is:
  timestamp,src_ip,dst_ip,port,status

Example:
  2025-12-06T12:00:01Z,10.0.0.5,10.0.0.10,22,FAIL

The project demonstrates how to use:
  • deque<Event> as a sliding time window
  • unordered_map<string, HostState> for fast per-host lookup
  • adjacency lists (neighbors per host) for connection relationships
  • unordered_set<int> to track distinct ports per src->dst pair

2. File Structure
-----------------
src/
  flowguard.cpp  - main detector program
  generator.cpp  - generates synthetic test logs

Generated at runtime:
  portscan.log   - should trigger a port scan alert
  bruteforce.log - should trigger a brute-force alert
  spike.log      - should trigger a spike alert

3. Build
--------
From the FlowGuard directory (with src/ inside it):

  g++ src/flowguard.cpp -std=c++17 -o flowguard
  g++ src/generator.cpp -std=c++17 -o generator

4. Generate Test Logs
---------------------
Port scan:
  ./generator port > portscan.log

Brute force:
  ./generator brute > bruteforce.log

Traffic spike:
  ./generator spike > spike.log

5. Run FlowGuard
----------------
Port scan detection:
  ./flowguard portscan.log

Brute-force detection:
  ./flowguard bruteforce.log

Spike detection:
  ./flowguard spike.log

6. High-Level Logic
-------------------
• FlowGuard keeps a sliding time window of recent events using deque<Event>.
• For each event, it:
    1) Inserts the event into the deque.
    2) Removes any events older than WINDOW_SECONDS.
    3) Updates per-host and per-neighbor statistics in hash maps.
    4) Checks three detection rules:

       - Port scan:
         many distinct ports from src -> dst in the window.

       - Brute force:
         many failed attempts for src -> dst:port in the window.

       - Traffic spike:
         many total connections to a single destination in the window.

• All updates are O(1) average time, so the whole log is processed in O(N).

7. Limitations (Cons)
---------------------
• Only uses connection metadata, not packet payloads.
• Cannot detect fileless malware, memory-only attacks, or LOLBin abuse.
• Cannot see malicious content hidden entirely inside TLS/HTTPS.
• Sliding window discards older history, so very slow attacks may not be detected.
• No correlation across multiple different log sources.

8. Strengths (Pros)
-------------------
• Fully automated and runs in one pass over the log.
• Uses standard data structures: deque, unordered_map, unordered_set.
• Detects common "noisy" intrusion behaviors (scan, brute force, spikes).
• Code is modular and easy to extend with more rules.
