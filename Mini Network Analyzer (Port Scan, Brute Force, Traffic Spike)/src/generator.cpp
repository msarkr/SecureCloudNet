#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>

using namespace std;

// Build a timestamp "2025-12-06THH:MM:SSZ"
string make_ts(int base_hour, int base_minute, int offset_seconds) {
    int total = base_hour * 3600 + base_minute * 60 + offset_seconds;

    int h = (total / 3600) % 24;
    int m = (total / 60) % 60;
    int s = total % 60;

    ostringstream oss;
    oss << "2025-12-06T"
        << setw(2) << setfill('0') << h << ":"
        << setw(2) << setfill('0') << m << ":"
        << setw(2) << setfill('0') << s << "Z";
    return oss.str();
}

// Port scan: one src hits many ports on one dst quickly
void gen_portscan() {
    string src = "10.0.0.5";
    string dst = "10.0.0.10";
    int base_hour = 12;
    int base_min = 0;

    for (int i = 0; i < 12; i++) {      // 12 ports -> >= 10 threshold
        string ts = make_ts(base_hour, base_min, i);
        int port = 1000 + i;
        cout << ts << "," << src << "," << dst << "," << port << ",OK\n";
    }
}

// Brute force: repeated FAILs to same dst:port
void gen_bruteforce() {
    string src = "10.0.0.8";
    string dst = "10.0.0.11";
    int port   = 22;
    int base_hour = 12;
    int base_min = 5;

    for (int i = 0; i < 7; i++) {       // 7 fails -> >= 5 threshold
        string ts = make_ts(base_hour, base_min, i);
        cout << ts << "," << src << "," << dst << "," << port << ",FAIL\n";
    }
}

// Spike: many connections to same dst in a short period
void gen_spike() {
    string dst = "10.0.0.20";
    int base_hour = 12;
    int base_min = 10;

    for (int i = 0; i < 80; i++) {      // 80 connections -> >= 30 threshold
        string ts = make_ts(base_hour, base_min, i);
        string src = "10.0.0." + to_string(100 + (i % 10));
        int port = 80;
        cout << ts << "," << src << "," << dst << "," << port << ",OK\n";
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <mode>\n";
        cerr << "  modes: port | brute | spike\n";
        return 1;
    }

    string mode = argv[1];
    if (mode == "port") {
        gen_portscan();
    } else if (mode == "brute") {
        gen_bruteforce();
    } else if (mode == "spike") {
        gen_spike();
    } else {
        cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }

    return 0;
}
