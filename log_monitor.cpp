// log_monitor.cpp
// Log Monitoring & Alert System in C++
// Features:
// - Reads a log file (system.log by default)
// - Detects "Failed password", "Error", "Critical"
// - Tracks number of failed logins, errors, critical issues
// - Tracks suspicious IP addresses
// - Saves alerts to alerts.log
// - Realtime monitoring (scans new lines every few seconds)
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>

using namespace std;

// ANSI colors (for pretty output in terminal)
string RED   = "\033[31m";
string YEL   = "\033[33m";
string GRN   = "\033[32m";
string CYAN  = "\033[36m";
string DIM   = "\033[2m";
string RST   = "\033[0m";

// Convert string to lowercase
string to_lower_copy(string s) {
    for (auto &c : s) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

// Extract first IPv4-looking token (returns "" if none found)
string extract_ip(const string& line) {
    static const regex ipre(R"((\b\d{1,3}(?:\.\d{1,3}){3}\b))");
    smatch m;
    if (regex_search(line, m, ipre)) return m[0];
    return "";
}

struct Config {
    string filename = "system.log";
    int failed_threshold = 3;
    bool color = true;
};

struct Counters {
    long long failed_logins = 0;
    long long errors = 0;
    long long criticals = 0;
    unordered_map<string, long long> ipCount;
};

void parse_args(int argc, char** argv, Config& cfg) {
    for (int i=1; i<argc; i++) {
        string a = argv[i];
        if (a=="--file" && i+1<argc) cfg.filename = argv[++i];
        else if (a=="--failed" && i+1<argc) cfg.failed_threshold = stoi(argv[++i]);
        else if (a=="--no-color") cfg.color = false;
        else if (a=="--help") {
            cout <<
"Usage:\n"
"  ./log_monitor [--file system.log] [--failed 3] [--no-color]\n";
            exit(0);
        }
    }
    if (!cfg.color) RED=YEL=GRN=CYAN=DIM=RST="";
}

bool scan_file(const Config& cfg, Counters& total, ofstream& alertOut) {
    ifstream fin(cfg.filename);
    if (!fin.is_open()) {
        cerr << "❌ Failed to open " << cfg.filename << "\n";
        return false;
    }

    bool alerted = false;
    long long failed_this=0, errors_this=0, criticals_this=0;
    unordered_map<string,long long> ip_this;
    string line;

    while (getline(fin, line)) {
        string lower = to_lower_copy(line);
        if (lower.find("failed password") != string::npos) {
            failed_this++; total.failed_logins++;
            string ip = extract_ip(line);
            if (!ip.empty()) {
                total.ipCount[ip]++;
                ip_this[ip]++;
            }
        }
        if (lower.find("error") != string::npos) { errors_this++; total.errors++; }
        if (lower.find("critical") != string::npos) { criticals_this++; total.criticals++; }
    }

    fin.close();

    cout << "\n----------------------------------\n";
    cout << "Scan Results:\n";
    cout << "  Failed logins: " << failed_this << "\n";
    cout << "  Errors:        " << errors_this << "\n";
    cout << "  Criticals:     " << criticals_this << "\n";
    cout << "----------------------------------\n";

    if (failed_this > cfg.failed_threshold) {
        cout << YEL << "⚠️ ALERT: Multiple failed logins ("<<failed_this<<")\n" << RST;
        alertOut << "ALERT: Multiple failed logins ("<<failed_this<<")\n";
        alerted = true;
    }
    if (errors_this > 0) {
        cout << YEL << "⚠️ ALERT: " << errors_this << " error(s)\n" << RST;
        alertOut << "ALERT: " << errors_this << " error(s)\n";
        alerted = true;
    }
    if (criticals_this > 0) {
        cout << RED << "🚨 CRITICAL: " << criticals_this << " critical issue(s)\n" << RST;
        alertOut << "CRITICAL: " << criticals_this << " critical issue(s)\n";
        alerted = true;
    }

    if (!ip_this.empty()) {
        cout << "\n🔎 Suspicious IPs:\n";
        vector<pair<string,long long>> v(ip_this.begin(), ip_this.end());
        sort(v.begin(), v.end(), [](auto&a,auto&b){return a.second>b.second;});
        for (auto &p : v) {
            cout << "   " << p.first << " → " << p.second << " attempts\n";
        }
    }

    if (alerted) {
        alertOut << "----\n"; alertOut.flush();
        cout << GRN << "✅ Alerts saved to alerts.log\n" << RST;
    }

    return alerted;
}

int main(int argc, char** argv) {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    Config cfg;
    parse_args(argc, argv, cfg);

    cout << CYAN << "[INFO] Starting Log Monitor\n" << RST;
    cout << "File: " << cfg.filename << "\n";
    cout << "Failed-login threshold: " << cfg.failed_threshold << "\n";
    cout << "Mode: single-scan\n\n";

    ofstream alertOut("alerts.log", ios::app);
    if (!alertOut.is_open()) {
        cerr << "❌ Could not open alerts.log\n";
        return 1;
    }

    Counters total;
    scan_file(cfg,total,alertOut);

    return 0;
}
