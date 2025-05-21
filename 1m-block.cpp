#include <cstdio>        // for FILE, fopen, fclose, printf
#include <cstdlib>       // for exit, malloc
#include <cstring>       // for strcmp, strstr, strlen, strncpy, etc.
#include <csignal>       // for signal, SIGINT
#include <unistd.h>      // for getopt, optind
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <errno.h>
#include <string>
#include <unordered_set>
#include <fstream>
#include <iostream>
#include <sstream>
#include <chrono>        // for std::chrono
#include <algorithm>     // for std::transform
#include <netinet/ip.h>     // struct iphdr
#include <netinet/tcp.h>    // struct tcphdr

bool verbose = false;
std::unordered_set<std::string> blocked_domains;
long domains_loaded = 0;
long blocks_count = 0;

void print_memory_status(const char* label) {
    FILE* file = fopen("/proc/meminfo", "r");
    if (!file) {
        perror("fopen");
        return;
    }

    unsigned long memTotal = 0, memFree = 0, buffers = 0, cached = 0;
    char key[64];
    unsigned long val;
    char unit[16];

    while (fscanf(file, "%63s %lu %15s\n", key, &val, unit) == 3) {
        if (strcmp(key, "MemTotal:") == 0) memTotal = val;
        else if (strcmp(key, "MemFree:") == 0) memFree = val;
        else if (strcmp(key, "Buffers:") == 0) buffers = val;
        else if (strcmp(key, "Cached:") == 0) cached = val;
    }

    fclose(file);

    unsigned long used = memTotal - memFree - buffers - cached;

    printf("\n[%s]\n", label);
    printf("🧠 Total RAM  : %10lu KB\n", memTotal);
    printf("💤 Free RAM   : %10lu KB\n", memFree);
    printf("📦 Buffers    : %10lu KB\n", buffers);
    printf("🧊 Cached     : %10lu KB\n", cached);
    printf("🔥 Used RAM   : %10lu KB\n", used);
}

void print_usage(const char* prog) {
    printf("Usage: %s [-v] <blocklist_file>\n", prog);
    printf("Options:\n  -v\tVerbose mode\n");
}

void sigint_handler(int sig) {
    printf("\n⚠️ Interrupt received. Cleaning up...\n");
    printf("📌 Domains loaded: %ld\n", domains_loaded);
    printf("🚫 Requests blocked: %ld\n", blocks_count);
    print_memory_status("📉 Final memory state");
    exit(0);
}

void load_blocklist(const char* filename) {
    auto start = std::chrono::steady_clock::now();
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "❌ Failed to open file: " << filename << "\n";
        exit(1);
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t comma = line.find(',');
        if (comma != std::string::npos) {
            std::string domain = line.substr(comma + 1);
            domain.erase(domain.find_last_not_of("\r\n") + 1);
            std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
            blocked_domains.insert(domain);
            domains_loaded++;
        }
    }
    file.close();
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration<double>(end - start);
    printf("\n📂 Blocklist loaded in %.3f seconds\n", duration.count());
    printf("📄 Total sites loaded: %ld\n", domains_loaded);
    print_memory_status("📊 After loading blocklist");
}

bool extract_host(const unsigned char* http_data, int http_len, std::string& host_out) {
    const char* host_header = "Host: ";
    const char* http = (const char*)http_data;
    const char* found = strstr(http, host_header);
    if (!found) return false;
    const char* start = found + strlen(host_header);
    const char* end = strstr(start, "\r\n");
    if (!end) return false;
    std::string raw_host(start, end - start);
    size_t colon = raw_host.find(':');
    if (colon != std::string::npos) raw_host = raw_host.substr(0, colon);
    std::transform(raw_host.begin(), raw_host.end(), raw_host.begin(), ::tolower);
    host_out = raw_host;
    return true;
}

bool is_http_request(const unsigned char* http) {
    const char* methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH"};
    for (const char* method : methods) {
        if (strncmp((char*)http, method, strlen(method)) == 0) {
            return true;
        }
    }
    return false;
}

u_int32_t inspect_packet(struct nfq_data* tb, bool& should_block) {
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(tb);
    if (ph) id = ntohl(ph->packet_id);

    unsigned char* data;
    int len = nfq_get_payload(tb, &data);
    if (len >= 0) {
        struct iphdr* iphdr = (struct iphdr*)data;
        if (iphdr->protocol != IPPROTO_TCP) return id;
        int ip_hdr_len = iphdr->ihl * 4;
        struct tcphdr* tcphdr = (struct tcphdr*)(data + ip_hdr_len);
        if (ntohs(tcphdr->dest) != 80) return id;
        int tcp_hdr_len = tcphdr->doff * 4;
        int http_offset = ip_hdr_len + tcp_hdr_len;
        int http_len = len - http_offset;
        if (http_len <= 0) return id;
        unsigned char* http = data + http_offset;

        if (is_http_request(http)) {
            std::string host;
            auto start = std::chrono::steady_clock::now();
            if (extract_host(http, http_len, host)) {
                bool found = blocked_domains.count(host);
                auto end = std::chrono::steady_clock::now();
                double ms = std::chrono::duration<double, std::milli>(end - start).count();
                if (found) {
                    blocks_count++;
                    printf("🚫 BLOCKED [%.3f ms] → %s\n", ms, host.c_str());
                    should_block = true;
                } else if (verbose) {
                    printf("✅ ALLOWED [%.3f ms] → %s\n", ms, host.c_str());
                }
            }
        }
    }
    return id;
}

int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data) {
    bool should_block = false;
    u_int32_t id = inspect_packet(nfa, should_block);
    return nfq_set_verdict(qh, id, should_block ? NF_DROP : NF_ACCEPT, 0, NULL);
}

int main(int argc, char** argv) {
    signal(SIGINT, sigint_handler);

    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        if (opt == 'v') verbose = true;
        else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (optind >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char* blocklist_file = argv[optind];
    printf("📥 Loading blocklist file: %s\n", blocklist_file);
    load_blocklist(blocklist_file);

    struct nfq_handle* h = nfq_open();
    if (!h) { perror("nfq_open"); exit(1); }
    if (nfq_unbind_pf(h, AF_INET) < 0) { perror("nfq_unbind_pf"); exit(1); }
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); exit(1); }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) { perror("nfq_create_queue"); exit(1); }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); exit(1);
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    printf("🛡️  Filtering started. Use Ctrl+C to stop.\n");

    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    perror("recv failed");
    nfq_destroy_queue(qh);
    nfq_close(h);

    printf("👋 Exiting.\n");
    return 0;
}

