#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <regex>
#include <ctime>
#include <cstdio>

using namespace std;

/*
  Log Parser & Alert Generator (portable C++11)
  - Reads a log file
  - Counts FAILED LOGINs by IP
  - Flags IPs with N+ failures within W seconds (sliding window)
  - Summarizes WARN/ERROR
  Build (Linux/macOS/MinGW): g++ -std=c++11 -O2 log_parser.cpp -o log_parser
  Run: ./log_parser sample.log --window=60 --threshold=3 --out=alerts.csv
*/

struct Args {
    string infile;
    int windowSec = 60;     // --window=SECONDS
    int threshold = 3;      // --threshold=N
    string outCsv;          // --out=alerts.csv (optional)
};

static bool starts_with(const string& s, const string& pref) {
    return s.size() >= pref.size() && equal(pref.begin(), pref.end(), s.begin());
}

static bool parse_kv(const string& a, const string& key, int& out) {
    if (starts_with(a, key)) {
        try {
            out = stoi(a.substr(key.size()));
            return true;
        } catch (...) { return false; }
    }
    return false;
}

static bool parse_kv(const string& a, const string& key, string& out) {
    if (starts_with(a, key)) {
        out = a.substr(key.size());
        return true;
    }
    return false;
}

static bool parseArgs(int argc, char** argv, Args& args) {
    if (argc < 2) return false;
    args.infile = argv[1];
    for (int i = 2; i < argc; ++i) {
        string a = argv[i];
        if (parse_kv(a, "--window=", args.windowSec)) continue;
        if (parse_kv(a, "--threshold=", args.threshold)) continue;
        if (parse_kv(a, "--out=", args.outCsv)) continue;
        cerr << "Unknown arg: " << a << "\n";
        return false;
    }
    if (args.windowSec <= 0 || args.threshold <= 0) return false;
    return true;
}

// Parse leading "[YYYY-MM-DD HH:MM:SS]" -> time_t
static bool parseTimestamp(const string& line, time_t& t) {
    if (line.size() < 21 || line[0] != '[') return false;
    // substring "YYYY-MM-DD HH:MM:SS"
    string ts = line.substr(1, 19);
    int Y,M,D,h,m,s;
    if (sscanf(ts.c_str(), "%d-%d-%d %d:%d:%d", &Y,&M,&D,&h,&m,&s) != 6) return false;
    std::tm tm{};
    tm.tm_year = Y - 1900;
    tm.tm_mon  = M - 1;
    tm.tm_mday = D;
    tm.tm_hour = h;
    tm.tm_min  = m;
    tm.tm_sec  = s;
    t = mktime(&tm); // local time; for UTC use timegm if available
    return t != (time_t)-1;
}

// Extract IPv4 after "from " (case-insensitive)
static string extractIP(const string& line) {
    static const regex ipre(R"(from\s+(\d{1,3}(?:\.\d{1,3}){3}))",
                            std::regex_constants::icase);
    smatch m;
    if (regex_search(line, m, ipre)) return m[1].str();
    return "";
}

// lowercase helper (ASCII)
static string to_lower_copy(string s) {
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') s[i] = char(c - 'A' + 'a');
    }
    return s;
}

int main(int argc, char** argv) {
    ios::sync_with_stdio(false);

    Args args;
    if (!parseArgs(argc, argv, args)) {
        cerr << "Usage: " << argv[0]
             << " <logfile> [--window=SECONDS] [--threshold=N] [--out=alerts.csv]\n";
        return 1;
    }

    ifstream in(args.infile.c_str());
    if (!in) {
        cerr << "Error: cannot open input file: " << args.infile << "\n";
        return 2;
    }

    long long totalLines = 0;
    long long failedLogins = 0, warnCount = 0, errorCount = 0;

    unordered_map<string, vector<time_t> > ipFails;
    ipFails.reserve(1024);

    string line;
    while (std::getline(in, line)) {
        ++totalLines;

        string lower = to_lower_copy(line);
        // Count WARN/ERROR (simple contains checks)
        if (lower.find(" warn ") != string::npos ||
            (starts_with(lower, "[") && lower.find("] warn ") != string::npos))
            ++warnCount;

        if (lower.find(" error ") != string::npos ||
            (starts_with(lower, "[") && lower.find("] error ") != string::npos))
            ++errorCount;

        // FAILED LOGIN lines
        if (lower.find("failed login") != string::npos) {
            string ip = extractIP(line);
            time_t ts{};
            if (!ip.empty() && parseTimestamp(line, ts)) {
                ++failedLogins;
                ipFails[ip].push_back(ts);
            }
        }
    }
    in.close();

    // Sort timestamps per IP
    for (auto& kv : ipFails) sort(kv.second.begin(), kv.second.end());

    // Sliding-window burst detection
    struct Offender { string ip; time_t firstSeen; time_t lastSeen; int count; };
    vector<Offender> offenders;

    for (auto& kv : ipFails) {
        const string& ip = kv.first;
        const vector<time_t>& v = kv.second;
        size_t l = 0;
        for (size_t r = 0; r < v.size(); ++r) {
            while (v[r] - v[l] > args.windowSec) ++l;
            int windowCount = int(r - l + 1);
            if (windowCount >= args.threshold) {
                offenders.push_back(Offender{ip, v[l], v[r], windowCount});
                ++l; // advance to find additional bursts
            }
        }
    }

    // Sort offenders (count desc, lastSeen desc)
    sort(offenders.begin(), offenders.end(),
         [](const Offender& a, const Offender& b){
             if (a.count != b.count) return a.count > b.count;
             return a.lastSeen > b.lastSeen;
         });

    // Output summary
    cout << "Analyzed: " << args.infile << "\n";
    cout << "Lines: " << totalLines
         << " | FAILED LOGINs: " << failedLogins
         << " | WARN: " << warnCount
         << " | ERROR: " << errorCount << "\n";

    // Top totals by IP
    vector<pair<string,int> > topTotals;
    topTotals.reserve(ipFails.size());
    for (auto& kv : ipFails)
        topTotals.push_back(make_pair(kv.first, (int)kv.second.size()));
    sort(topTotals.begin(), topTotals.end(),
         [](const pair<string,int>& a, const pair<string,int>& b){
             if (a.second != b.second) return a.second > b.second;
             return a.first < b.first;
         });

    cout << "\nTop failed-login IPs:\n";
    if (topTotals.empty()) {
        cout << "  (none)\n";
    } else {
        int show = (int)min<size_t>(5, topTotals.size());
        for (int i = 0; i < show; ++i)
            cout << "  " << topTotals[i].first << " : " << topTotals[i].second << "\n";
    }

    cout << "\nBurst offenders (" << args.threshold
         << "+ fails within " << args.windowSec << "s):\n";
    if (offenders.empty()) {
        cout << "  (none)\n";
    } else {
        char buf1[32], buf2[32];
        for (size_t i = 0; i < offenders.size(); ++i) {
            const Offender& o = offenders[i];
            strftime(buf1, sizeof(buf1), "%F %T", localtime(&o.firstSeen));
            strftime(buf2, sizeof(buf2), "%F %T", localtime(&o.lastSeen));
            cout << "  " << o.ip
                 << " | first=" << buf1
                 << " | last="  << buf2
                 << " | count=" << o.count << "\n";
        }
    }

    // Optional CSV export
    if (!args.outCsv.empty()) {
        ofstream out(args.outCsv.c_str());
        if (!out) {
            cerr << "Error: cannot open output file: " << args.outCsv << "\n";
            return 3;
        }
        out << "ip,first_seen,last_seen,count,window_seconds,threshold\n";
        char b1[32], b2[32];
        for (size_t i = 0; i < offenders.size(); ++i) {
            const Offender& o = offenders[i];
            strftime(b1, sizeof(b1), "%F %T", localtime(&o.firstSeen));
            strftime(b2, sizeof(b2), "%F %T", localtime(&o.lastSeen));
            out << o.ip << ","
                << b1 << ","
                << b2 << ","
                << o.count << ","
                << args.windowSec << ","
                << args.threshold << "\n";
        }
        out.close();
        cout << "\nExported offenders to: " << args.outCsv << "\n";
    }

    return 0;
}
