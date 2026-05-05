#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <strings.h>
#include <cerrno>
#include <cstdlib>
#include <cstdint>

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define IPV4_PROTOCOL_TCP 6
#define HTTP_PORT 80

#pragma pack(push, 1)

struct Ipv4Hdr
{
    uint8_t  vhl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

struct TcpHdr
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t  off_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

#pragma pack(pop)

static std::unordered_set<std::string> bad_hosts;

static void usage()
{
    std::cout << "syntax : 1m-block <site list file>\n";
    std::cout << "sample : 1m-block top-1m.csv\n";
}

static void trim(std::string& s)
{
    while(!s.empty() &&
          (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();

    size_t start = 0;

    while(start < s.size() && (s[start] == ' ' || s[start] == '\t'))
        start++;

    if(start > 0)
        s.erase(0, start);
}

static bool all_digits(const std::string& s, size_t start)
{
    if(start >= s.size())
        return false;

    for(size_t i = start; i < s.size(); i++)
    {
        if(!std::isdigit(static_cast<unsigned char>(s[i])))
            return false;
    }

    return true;
}

static std::string normalize_host(std::string host)
{
    trim(host);

    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c)
                   {
                       return static_cast<char>(std::tolower(c));
                   });

    if(!host.empty() && host.back() == '.')
        host.pop_back();

    size_t colon = host.rfind(':');

    if(colon != std::string::npos && host.find('[') == std::string::npos && all_digits(host, colon + 1))
        host.erase(colon);

    return host;
}

static bool load_bad_hosts(const char* file_name, double& load_sec)
{
    auto start = std::chrono::steady_clock::now();

    std::ifstream file(file_name);

    if(!file.is_open())
    {
        std::cerr << "open failed: " << file_name << "\n";
        return false;
    }

    bad_hosts.clear();
    bad_hosts.max_load_factor(0.7);
    bad_hosts.reserve(1000000);

    std::string line;

    while(std::getline(file, line))
    {
        if(line.empty())
            continue;

        size_t comma = line.find(',');
        std::string domain = (comma == std::string::npos) ? line : line.substr(comma + 1);

        domain = normalize_host(domain);

        if(!domain.empty())
            bad_hosts.insert(domain);
    }

    auto end = std::chrono::steady_clock::now();
    load_sec = std::chrono::duration<double>(end - start).count();

    return true;
}

static bool is_http_request(const unsigned char* http, int http_len)
{
    return (http_len >= 4 && std::memcmp(http, "GET ", 4) == 0) ||
           (http_len >= 5 && std::memcmp(http, "POST ", 5) == 0) ||
           (http_len >= 5 && std::memcmp(http, "HEAD ", 5) == 0);
}

static bool extract_host(const unsigned char* http, int http_len, std::string& host)
{
    host.clear();

    if(http == nullptr || http_len <= 0)
        return false;

    if(!is_http_request(http, http_len))
        return false;

    const char* data = reinterpret_cast<const char*>(http);

    for(int i = 0; i + 5 <= http_len; i++)
    {
        bool line_start = (i == 0 || data[i - 1] == '\n');

        if(!line_start)
            continue;

        if(strncasecmp(data + i, "Host:", 5) != 0)
            continue;

        int start = i + 5;

        while(start < http_len && (data[start] == ' ' || data[start] == '\t'))
            start++;

        int end = start;

        while(end < http_len && data[end] != '\r' && data[end] != '\n')
            end++;

        if(end <= start)
            return false;

        host.assign(data + start, end - start);
        return true;
    }

    return false;
}

static uint32_t get_packet_id(struct nfq_data* tb)
{
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(tb);

    if(ph == nullptr)
        return 0;

    return ntohl(ph->packet_id);
}

static int set_verdict(struct nfq_q_handle* qh, uint32_t id, uint32_t verdict)
{
    return nfq_set_verdict(qh, id, verdict, 0, nullptr);
}

static bool is_fragmented(const Ipv4Hdr* ip)
{
    uint16_t frag = ntohs(ip->frag_off);
    return (frag & 0x3FFF) != 0;
}

static bool should_drop(unsigned char* data, int len, std::string& captured_host, long long& search_ns)
{
    captured_host.clear();
    search_ns = 0;

    if(data == nullptr || len < static_cast<int>(sizeof(Ipv4Hdr)))
        return false;

    Ipv4Hdr* ip = reinterpret_cast<Ipv4Hdr*>(data);

    uint8_t ip_version = ip->vhl >> 4;
    int ip_hdr_len = (ip->vhl & 0x0F) * 4;
    uint16_t ip_total_len = ntohs(ip->total_len);

    if(ip_version != 4 || ip_hdr_len < 20 || ip_total_len < ip_hdr_len)
        return false;

    int cap_len = len < ip_total_len ? len : ip_total_len;

    if(cap_len < ip_hdr_len + static_cast<int>(sizeof(TcpHdr)))
        return false;

    if(is_fragmented(ip) || ip->protocol != IPV4_PROTOCOL_TCP)
        return false;

    TcpHdr* tcp = reinterpret_cast<TcpHdr*>(data + ip_hdr_len);

    int tcp_hdr_len = ((tcp->off_reserved >> 4) & 0x0F) * 4;

    if(tcp_hdr_len < 20 || cap_len < ip_hdr_len + tcp_hdr_len)
        return false;

    if(ntohs(tcp->dport) != HTTP_PORT)
        return false;

    unsigned char* http = data + ip_hdr_len + tcp_hdr_len;
    int http_len = cap_len - ip_hdr_len - tcp_hdr_len;

    if(!extract_host(http, http_len, captured_host))
        return false;

    std::string key = normalize_host(captured_host);

    auto start = std::chrono::steady_clock::now();
    bool found = bad_hosts.find(key) != bad_hosts.end();
    auto end = std::chrono::steady_clock::now();

    search_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    return found;
}

static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
              struct nfq_data* nfa, void* user_data)
{
    (void)nfmsg;
    (void)user_data;

    uint32_t id = get_packet_id(nfa);

    unsigned char* data = nullptr;
    int payload_len = nfq_get_payload(nfa, &data);

    if(payload_len < 0)
        return set_verdict(qh, id, NF_ACCEPT);

    std::string host;
    long long search_ns = 0;

    bool drop = should_drop(data, payload_len, host, search_ns);

    if(!host.empty())
        std::cout << (drop ? "DROP " : "ACCEPT ")
                  << host << " "
                  << search_ns << "ns\n";

    return set_verdict(qh, id, drop ? NF_DROP : NF_ACCEPT);
}

int main(int argc, char** argv)
{
    if(argc != 2)
    {
        usage();
        return 1;
    }

    std::cout << "pid=" << getpid() << "\n";

    double load_sec = 0.0;

    if(!load_bad_hosts(argv[1], load_sec))
        return 1;

    std::cout << "loaded=" << bad_hosts.size()
              << " load=" << load_sec << "s\n";

    struct nfq_handle* h = nfq_open();

    if(h == nullptr)
    {
        std::cerr << "nfq_open failed\n";
        return 1;
    }

    if(nfq_unbind_pf(h, AF_INET) < 0)
    {
        std::cerr << "nfq_unbind_pf failed\n";
        nfq_close(h);
        return 1;
    }

    if(nfq_bind_pf(h, AF_INET) < 0)
    {
        std::cerr << "nfq_bind_pf failed\n";
        nfq_close(h);
        return 1;
    }

    struct nfq_q_handle* qh = nfq_create_queue(h, 0, &cb, nullptr);

    if(qh == nullptr)
    {
        std::cerr << "nfq_create_queue failed\n";
        nfq_close(h);
        return 1;
    }

    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        std::cerr << "nfq_set_mode failed\n";
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    int fd = nfq_fd(h);
    alignas(4096) char buf[65536];

    std::cout << "ready\n\n";

    while(true)
    {
        int rv = recv(fd, buf, sizeof(buf), 0);

        if(rv >= 0)
        {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if(errno == ENOBUFS)
        {
            std::cerr << "ENOBUFS\n";
            continue;
        }

        perror("recv");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}
