#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define IP4_ALEN	4
#define ARRAY_SIZE(x)	(sizeof(x)/sizeof(x[0]))

typedef struct ethhdr ethhdr_t;

typedef struct eth_ipv4_arphdr {
	uint16_t	ar_hrd;			/* format of hardware address */
	uint16_t	ar_pro;			/* format of protocol address */
	uint8_t		ar_hln;			/* length of hardware address */
	uint8_t		ar_pln;			/* length of protocol address */
	uint16_t	ar_op;			/* ARP opcode (command) */
	uint8_t		ar_sha[ETH_ALEN];	/* sender hardware address */
	uint8_t		ar_sip[IP4_ALEN];	/* sender IP address */
	uint8_t		ar_tha[ETH_ALEN];	/* target hardware address */
	uint8_t		ar_tip[IP4_ALEN];	/* target IP address */
} arphdr_t;

typedef struct ifinfo {
	int		index;
	uint8_t		ipaddr[IP4_ALEN];
	uint8_t		hwaddr[ETH_ALEN];
} ifinfo_t;

const struct arp_map {
	uint8_t ipaddr[IP4_ALEN];
	uint8_t hwaddr[ETH_ALEN];
} arp_map[] = {
	{{192, 168, 1, 201}, {0x00, 0xD8, 0x61, 0x15, 0xF5, 0xE8}},
	{{192, 168, 1, 202}, {0xD8, 0xCB, 0x8A, 0x80, 0x7A, 0xC8}},
};

struct options {
	char *ifname;
	char *output;
	bool help;
} args = {
	.ifname = NULL,
	.output = NULL,
	.help = false
};

const char *short_args = "o:hv";
const struct option long_args[] = {
	{"output", required_argument, NULL, 'o'},
	{"help", no_argument, NULL, 'h'},
};

int get_stream(FILE **stream)
{
	*stream = stdout;
	if (args.output == NULL)
		return 0;

	*stream = fopen(args.output, "a");
	if (*stream != NULL)
		return 0;

	perror("fopen()");
	return 1;
}

void release_stream(FILE *stream)
{
	if (args.output != NULL && stream != stdout && stream != stderr)
		fclose(stream);
}

void log_help(const char *procname, bool full)
{
	FILE *stream = args.help ? stdout : stderr;

	fprintf(stream,
		"Usage: %s <ifname> [options]\n"
		"       %s [-h|--help] [-v|--version]\n", procname, procname);

	if (full) {
		fprintf(stream,
			"\n"
			"Listen on specified interface and reply ARP requests as desired.\n"
			"\n"
			"  -o, --output   <filename>  output the report to this specified file\n"
			"  -h, --help                 print this message and quit\n"
			"  -v, --version              print version information and quit\n");
	}
}

int log_welcome()
{
	FILE *stream;

	if (get_stream(&stream) != 0)
		return 1;

	fprintf(stream, "arplus started\n");

	release_stream(stream);
	return 0;
}

int log_eth_arp(ethhdr_t *eth)
{
	time_t timer;
	struct tm *ptm;
	arphdr_t *arp = (arphdr_t *)(eth + 1);
	FILE *stream;

	if (ntohs(arp->ar_op) != ARPOP_REQUEST && ntohs(arp->ar_op) != ARPOP_REPLY)
		return 1;

	if (get_stream(&stream) != 0)
		return 1;

	time(&timer);
	ptm = localtime(&timer);

	fprintf(stream, "[%04d-%02d-%02d %02d:%02d:%02d] ", ptm->tm_year + 1900, ptm->tm_mon + 1,
		ptm->tm_mday, ptm->tm_hour, ptm->tm_min, ptm->tm_sec);

	if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
		fprintf(stream, "Who has %hhu.%hhu.%hhu.%hhu? Tell %hhu.%hhu.%hhu.%hhu\n",
			arp->ar_tip[0], arp->ar_tip[1], arp->ar_tip[2], arp->ar_tip[3],
			arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3]);
	}
	if (ntohs(arp->ar_op) == ARPOP_REPLY) {
		fprintf(stream, "%hhu.%hhu.%hhu.%hhu is at %02X:%02X:%02X:%02X:%02X:%02X\n",
			arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3],
			arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2],
			arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);
	}

	release_stream(stream);
	return 0;
}

int log_error(const char *prefix)
{
	FILE *stream;

	if (get_stream(&stream) != 0)
		stream = stderr;

	fprintf(stream, "%s: %s\n", prefix, strerror(errno));

	release_stream(stream);
	return 0;
}

int get_args(int argc, char *argv[])
{
	int optch;
	int optid;

	while ((optch = getopt_long(argc, argv, short_args, long_args, &optid)) != -1) {
		switch (optch)
		{
		case 'o':
			args.output = optarg;
			break;
		case 'h':
			args.help = true;
			break;
		case '?':
			return -1;
		}
	}

	if (optind != argc - 1)
		return -1;

	args.ifname = argv[optind++];

	return 0;
}

int get_ifinfo(const char *ifname, ifinfo_t *ifinfo)
{
	int sockfd;
	struct ifreq ifr;

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd == -1) {
		log_error("socket()");
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
		log_error("SIOCGIFINDEX");
		return -1;
	}
	ifinfo->index = ifr.ifr_ifindex;

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == -1) {
		log_error("SIOCGIFADDR");
		return -1;
	}
	memcpy(ifinfo->ipaddr, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, IP4_ALEN);

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
		log_error("SIOCGIFHWADDR");
		return -1;
	}
	memcpy(ifinfo->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	close(sockfd);
	return 0;
}

int main(int argc, char *argv[])
{
	int sockfd;
	int ret;
	ssize_t len;
	uint8_t buffer[1500];
	char *procname = argv[0];
	struct sockaddr_ll sockaddr_ll;
	struct sockaddr *sockaddr = (struct sockaddr *)&sockaddr_ll;
	ifinfo_t ifinfo;
	ethhdr_t *eth = (ethhdr_t *)buffer;
	arphdr_t *arp = (arphdr_t *)(eth + 1);

	ret = get_args(argc, argv);
	if (ret == -1 || args.help) {
		log_help(procname, args.help);
		return !!ret;
	}

	log_welcome();

	if (get_ifinfo(args.ifname, &ifinfo) == -1)
		return 1;

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sockfd == -1) {
		log_error("socket()");
		return 1;
	}

	while (true) {
		len = recv(sockfd, buffer, sizeof(buffer), 0);
		if (len == -1) {
			log_error("recv()");
			return 1;
		}

		if ((arp->ar_hrd != htons(ARPHRD_ETHER) && arp->ar_hrd != htons(ARPHRD_IEEE802)) ||
				arp->ar_pro != htons(ETH_P_IP) || arp->ar_hln != ETH_ALEN ||
				arp->ar_pln != IP4_ALEN || arp->ar_op != htons(ARPOP_REQUEST))
			continue;

		for (int i = 0; i < ARRAY_SIZE(arp_map); i++) {
			if (memcmp(arp_map[i].ipaddr, arp->ar_tip, IP4_ALEN))
				continue;

			log_eth_arp(eth);

			memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
			memcpy(eth->h_source, ifinfo.hwaddr, ETH_ALEN);
			arp->ar_op = htons(ARPOP_REPLY);
			memcpy(arp->ar_tha, arp->ar_sha, ETH_ALEN);
			memcpy(arp->ar_tip, arp->ar_sip, IP4_ALEN);
			memcpy(arp->ar_sha, arp_map[i].hwaddr, ETH_ALEN);
			memcpy(arp->ar_sip, arp_map[i].ipaddr, IP4_ALEN);

			memset(&sockaddr_ll, 0, sizeof(sockaddr_ll));
			sockaddr_ll.sll_family = AF_PACKET;
			sockaddr_ll.sll_ifindex = ifinfo.index;
			sockaddr_ll.sll_halen = ETH_ALEN;
			memcpy(sockaddr_ll.sll_addr, ifinfo.hwaddr, ETH_ALEN);

			log_eth_arp(eth);

			if (sendto(sockfd, eth, len, 0, sockaddr, sizeof(sockaddr_ll)) == -1)
				log_error("sendto()");

			break;
		}
	}

	close(sockfd);
	return 0;
}
