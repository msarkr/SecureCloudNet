#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cctype>

using namespace std;

// default thresholds (can be overridden by profile)

const int window_seconds = 60;
const int port_scan = 10;     
const int fail = 5;   
const int spike = 30;  

// ---------- helpers ----------

string trim(const string &s) {
    int start = 0;
    int end = (int)s.size() - 1;

    while (start <= end &&
           (s[start] == ' ' || s[start] == '\t' ||
            s[start] == '\r' || s[start] == '\n')) {
        start++;
    }
    while (end >= start &&
           (s[end] == ' ' || s[end] == '\t' ||
            s[end] == '\r' || s[end] == '\n')) {
        end--;
    }
    if (start > end) return "";
    return s.substr(start, end - start + 1);
}

// simple string -> int (no exceptions)
int to_int(const string &raw) {
    string s = trim(raw);
    if (s.empty()) return 0;

    int sign = 1;
    int i = 0;
    if (s[0] == '-') {
        sign = -1;
        i = 1;
    }

    int val = 0;
    for (; i < (int)s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isdigit(c)) break;
        val = val * 10 + (c - '0');
    }
    return sign * val;
}

// Expect "YYYY-MM-DDTHH:MM:SSZ"
int parse_ts(const string &raw) {
    string s = trim(raw);
    if (s.size() < 19) return 0;

    string hh = s.substr(11, 2);
    string mm = s.substr(14, 2);
    string ss = s.substr(17, 2);

    int h   = to_int(hh);
    int m   = to_int(mm);
    int sec = to_int(ss);

    return h * 3600 + m * 60 + sec;
}

// ---------- core data ----------

struct Event {
    int ts;
    string src;
    string dst;
    int port;
    string status;
};

class FlowGuard {
public:
    FlowGuard(int win,
              int ps_threshold,
              int fail_threshold,
              int spike_threshold)
        : window_size(win),
          port_scan_threshold(ps_threshold),
          fail_threshold(fail_threshold),
          spike_threshold(spike_threshold) { }

    vector<string> process(const Event &e) {
        window.push_back(e);
        evict_old(e.ts);

        string key_sd  = e.src + "->" + e.dst;
        string key_sdp = key_sd + ":" + to_string(e.port);

        // update port-scan ports
        ps_ports[key_sd].insert(e.port);

        // update brute-force FAILs

        
        if (e.status == "FAIL") {
            bf_fails[key_sdp] = bf_fails[key_sdp] + 1;
        }

        // update spike counts
        dst_conn[e.dst] = dst_conn[e.dst] + 1;

        return detect(e, key_sd, key_sdp);
    }

private:
    int window_size;
    int port_scan_threshold;
    int fail_threshold;
    int spike_threshold;

    deque<Event> window; // sliding window of events

    // port scan: src->dst -> set of ports
    unordered_map<string, unordered_set<int> > ps_ports;

    // brute force: src->dst:port -> fail count
    unordered_map<string, int> bf_fails;

    // spike: dst -> connection count
    unordered_map<string, int> dst_conn;

    // to avoid spam
    unordered_set<string> ps_alerted;        // src->dst
    unordered_set<string> bf_alerted;        // src->dst:port
    unordered_map<string, int> spike_last;   // dst -> last level alerted

    void evict_old(int now) {
        int cutoff = now - window_size;

        while (!window.empty() && window.front().ts < cutoff) {
            Event old = window.front();
            window.pop_front();

            string key_sd  = old.src + "->" + old.dst;
            string key_sdp = key_sd + ":" + to_string(old.port);

            // adjust brute-force counts
            if (old.status == "FAIL") {
                unordered_map<string,int>::iterator it = bf_fails.find(key_sdp);
                if (it != bf_fails.end()) {
                    it->second = it->second - 1;
                    if (it->second <= 0) bf_fails.erase(it);
                }
            }

            // adjust spike counts
            unordered_map<string,int>::iterator it2 = dst_conn.find(old.dst);
            if (it2 != dst_conn.end()) {
                it2->second = it2->second - 1;
                if (it2->second <= 0) dst_conn.erase(it2);
            }

            // we leave ps_ports as an over-approximation (fine for demo).
        }
    }

    vector<string> detect(const Event &e,
                          const string &key_sd,
                          const string &key_sdp) {
        vector<string> alerts;

        // ---- port scan ----
        if (port_scan_threshold > 0) {
            unordered_map<string, unordered_set<int> >::iterator ps_it =
                ps_ports.find(key_sd);
            if (ps_it != ps_ports.end()) {
                int distinct = (int)ps_it->second.size();
                if (distinct >= port_scan_threshold &&
                    ps_alerted.find(key_sd) == ps_alerted.end()) {

                    ostringstream oss;
                    oss << "[ALERT][PORT SCAN] src=" << e.src
                        << " dst=" << e.dst
                        << " distinct_ports=" << distinct;
                    alerts.push_back(oss.str());
                    ps_alerted.insert(key_sd);
                }
            }
        }

        // ---- brute force ----


        if (fail_threshold > 0) {
            unordered_map<string,int>::iterator bf_it = bf_fails.find(key_sdp);
            if (bf_it != bf_fails.end()) {
                int fails = bf_it->second;
                if (fails >= fail_threshold && bf_alerted.find(key_sdp) == bf_alerted.end()) {

                    ostringstream oss;
                    oss << "[ALERT][BRUTE FORCE] src=" << e.src<< " dst=" << e.dst << ":" << e.port << " fails=" << fails;
                    alerts.push_back(oss.str());
                    bf_alerted.insert(key_sdp);
                }
            }
        }

        // ---- spike ----
        if (spike_threshold > 0) {
            unordered_map<string,int>::iterator sp_it = dst_conn.find(e.dst);
            if (sp_it != dst_conn.end()) {
                int cur = sp_it->second;
                int last = 0;
                if (spike_last.find(e.dst) != spike_last.end()) {
                    last = spike_last[e.dst];
                }

                if (cur >= spike_threshold &&
                    (last < spike_threshold || cur >= last + 10)) {
                    ostringstream oss;
                    oss << "[ALERT][SPIKE] dst=" << e.dst
                        << " connections=" << cur
                        << " in last " << window_size << "s";
                    alerts.push_back(oss.str());
                    spike_last[e.dst] = cur;
                }
            }
        }

        return alerts;
    }
};

// ---------- parsing ----------

bool parse_line(string &line_raw, Event &e) {
    string line = trim(line_raw);
    if (line.empty()) return false;

    string ts_str, src, dst, port_str, status;
    stringstream ss(line);

    if (!getline(ss, ts_str, ',')) return false;
    if (!getline(ss, src, ','))    return false;
    if (!getline(ss, dst, ','))    return false;
    if (!getline(ss, port_str, ',')) return false;
    if (!getline(ss, status, ',')) return false;

    ts_str   = trim(ts_str);
    src      = trim(src);
    dst      = trim(dst);
    port_str = trim(port_str);
    status   = trim(status);

    e.ts     = parse_ts(ts_str);
    e.src    = src;
    e.dst    = dst;
    e.port   = to_int(port_str);
    e.status = status;

    return true;
}

// ---------- main ----------

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <logfile> [profile]\n";
        cerr << "Profiles: port | brute | spike | all\n";
        return 1;
    }

    string path = argv[1];

    // default thresholds
    int win   = WINDOW_SECONDS_DEFAULT;
    int ps_th = PORT_SCAN_DEFAULT;
    int bf_th = FAIL_DEFAULT;
    int sp_th = SPIKE_DEFAULT;

    // optional profile argument
    if (argc >= 3) {
        string profile = argv[2];

        if (profile == "port") {
            // emphasize port-scan only
            ps_th = 3;      // trigger quickly
            bf_th = -1;     // disabled
            sp_th = -1;     // disabled
        } else if (profile == "brute") {
            ps_th = -1;     // disabled
            bf_th = 3;      // trigger quickly
            sp_th = -1;     // disabled
        } else if (profile == "spike") {
            ps_th = -1;     // disabled
            bf_th = -1;     // disabled
            sp_th = 30;     // spike demo
        } else if (profile == "all") {
            // use defaults – all detectors enabled
        } else {
            cerr << "Unknown profile: " << profile << "\n";
            return 1;
        }
    }

    ifstream in("portscan.log");
    
    
    // ifstream in(path.c_str());
    if (!in.is_open()) {
        cerr << "Cannot open file: " << path << "\n";
        return 1;
    }

    FlowGuard fg(win, ps_th, bf_th, sp_th);

    string line;
    while (getline(in, line)) {
        Event e;
        if (!parse_line(line, e)) continue;

        vector<string> alerts = fg.process(e);

        for (int i = 0; i < (int)alerts.size(); i++) {
            cout << line.substr(0, 19) << " " << alerts[i] << "\n";
        }
    }

    return 0;
}
