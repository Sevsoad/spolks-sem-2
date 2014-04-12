#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/cdefs.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>

void printPackage (char *package_pointer, int package_length, struct timeval *tvrecv);
void pinger ();
void catcher (int signum);
unsigned short calculateChecksum (unsigned short *addr, int len);
void timeValueSubstraction (struct timeval *out, struct timeval *in);
unsigned long resolve (char *hostname);

int socket_descriptor, packages_recieved = 0, packages_transmitted = 0;
int kBufferSize = sizeof (struct iphdr) + sizeof (struct icmp) + 100;
struct sockaddr_in destination_address;
unsigned long source_name, target_name;
struct hostent *host_name;

int main(int argc,char *argv[]) {
  if (argc != 3) {
    return printf("Error: wrong command.\n");
  }

  int buffer_size, n = 0;
  struct itimerval timer;
  struct sockaddr from;
  struct sigaction act;
  char recieve_buffer[kBufferSize];
  struct timeval tval;

  socket_descriptor = socket (PF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (socket_descriptor == -1) {
    return printf ("Unable to create socket.\n");
  }
  setuid (getuid());

  printf("\n%s", argv[1]);
  setsockopt (socket_descriptor, SOL_SOCKET, SO_RCVBUF, &buffer_size
              , sizeof (buffer_size));

  setsockopt (socket_descriptor, SOL_SOCKET, IP_HDRINCL, &buffer_size
              , sizeof (buffer_size));

  memset (&act,  0, sizeof(act));
  act.sa_handler = &catcher;
  sigaction (SIGALRM, &act, NULL);
  sigaction (SIGINT, &act, NULL);

  timer.it_value.tv_sec = 0;
  timer.it_value.tv_usec = 1;

  timer.it_interval.tv_sec = 1;
  timer.it_interval.tv_usec = 0;

  setitimer (ITIMER_REAL, &timer, NULL);

  bzero (&destination_address, sizeof(destination_address));
  destination_address.sin_family = AF_INET;
/*
  host_name = gethostbyname (argv[2]);
  if (host_name != NULL) {
    memcpy (&destination_address.sin_addr, host_name->h_addr, host_name->h_length);
  } else {
    printf ("\nhost_name error\n");
    return -1;
  }
*/

  source_name = resolve(argv[1]);
  target_name = resolve (argv[2]);
  destination_address.sin_addr.s_addr = target_name;

  while (1) {
    n = recvfrom(socket_descriptor, recieve_buffer,
                  sizeof(recieve_buffer), 0, 0, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      continue;
    }

    gettimeofday(&tval, NULL);
    printPackage(recieve_buffer, n, &tval);
    memset (&recieve_buffer, 0, kBufferSize);
  }

  return 0;
}

void catcher (int signum) {

  if (signum == SIGALRM) {
    pinger ();
    return;
  } else if (signum == SIGINT) {
    printf ("\n--- ping statistics --- \n");
    printf ("%d packets transmitted, %d recieved, %d%% packet loss\n",
             packages_transmitted, packages_recieved,
              (100 - (packages_recieved*100
                         / packages_transmitted)));
    exit (-1);
    return;
  }
}

void pinger () {
  int icmplen = 64, pid, package_number = 0;
  struct icmp *icmp;
  struct iphdr *ip_header;
  char sendbuf [kBufferSize];

  pid = getpid();

  ip_header = (struct iphdr *) sendbuf;
  ip_header->ihl = 5;
  ip_header->version = 4;
  ip_header->tot_len = htons (kBufferSize);
  ip_header->tos = 0;
  ip_header->id = 0;
  ip_header-> frag_off = 0;
  ip_header->ttl = 255;
  ip_header->protocol = IPPROTO_ICMP;
  ip_header->check = 0;
  ip_header->check = calculateChecksum ((unsigned short *) ip_header, sizeof (struct iphdr));
  ip_header->saddr = source_name;
  ip_header->daddr = target_name;

  icmp = (struct icmp *) (sendbuf + sizeof (struct iphdr));
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_id = pid;
  icmp->icmp_seq = package_number++;

  gettimeofday((struct timeval *) icmp->icmp_data, NULL);
  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = calculateChecksum ((unsigned short *) icmp, icmplen);

  if (sendto (socket_descriptor, sendbuf, icmplen, 0, (sockaddr *) &destination_address,
               (socklen_t ) sizeof(destination_address)) < 0) {
    printf("\nsendto() failed");
    exit (-1);
  }
  packages_transmitted++;
}


void printPackage (char *package_pointer, int package_length, struct timeval *tvrecv) {
  int ip_length, icmp_length;
  struct ip *ip_header;
  struct icmp *icmp_header;
  struct timeval *tvsend;
  double round_trip_time;

  ip_header = (struct ip *) package_pointer;
  ip_length = ip_header->ip_hl << 2;

  icmp_header = (struct icmp *) (package_pointer + ip_length);

  if ((icmp_length = package_length - ip_length) < 8) {
    return;
  }

  if (icmp_header->icmp_type == ICMP_ECHOREPLY) {
    if (icmp_header->icmp_id != getpid()) {
      return;
    if (package_length < 16) {
      printf ("length error\n");
      return;
    }
    }

    tvsend = (struct timeval *) icmp_header->icmp_data;
    timeValueSubstraction (tvrecv, tvsend);

    round_trip_time = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf ("%d bytes from %s: icmp_req=%u, ttl=%d, time=%.3f ms\n"
            , icmp_length,
            inet_ntoa (destination_address.sin_addr), ++packages_recieved,
            ip_header->ip_ttl, round_trip_time);
  }
}

unsigned short calculateChecksum (unsigned short * addr, int len) {
  unsigned short result;
  unsigned int sum = 0;
  uint16_t *w = addr;

  while (len > 1) {
    sum += *w++;
    len -= 2;
  }

  if (len == 1) {
    sum += *(unsigned char*) addr;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;

  return result;
}

void timeValueSubstraction (struct timeval *out, struct timeval *in) {
  if ((out->tv_usec -= in->tv_usec < 0)) {
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

unsigned long resolve (char *hostname) {
  struct hostent *hp;

  if ( (hp = gethostbyname (hostname)) == NULL) {
    printf ("\ngethostbyname() error");
    exit (-1);
  }

  return *(unsigned long *) hp->h_addr_list[0];
 }
