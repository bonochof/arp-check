#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

/**
 * convert mac address to formatted string
 * 
 * @param hwaddr mac address represented by uchar[]
 * @param buf string buffer
 * @param size size of string buffer
 * 
 * @return string for mac address
 **/
char *ether2str(u_char *hwaddr, char *buf, int size)
{
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
			 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	return (buf);
}

/**
 * convert ip address to string
 * @param ip ip address represented by u_int8_t[4]
 * @param buf string buffer
 * @param size size of string buffer
 * 
 * @return string for ip address
 **/
char *ip2str(u_int8_t *ip, char *buf, int size)
{
	snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	return (buf);
}

/**
 * print ether header
 * 
 * @param eh ether header
 * @param fp file descriptor for output
 * 
 **/
void print_ether_header(struct ether_header *eh, FILE *fp)
{
	char buf[80];

	fprintf(fp, "##### ETHER_HEADER #####\n");
	fprintf(fp, "ether_dhost=%s\n", ether2str(eh->ether_dhost, buf, sizeof(buf)));
	fprintf(fp, "ether_shost=%s\n", ether2str(eh->ether_shost, buf, sizeof(buf)));
	fprintf(fp, "ether_type=%02X", ntohs(eh->ether_type));
	switch (ntohs(eh->ether_type))
	{
	case ETH_P_IP:
		fprintf(fp, "(IP)\n");
		break;
	case ETH_P_IPV6:
		fprintf(fp, "(IPv6)\n");
		break;
	case ETH_P_ARP:
		fprintf(fp, "(ARP)\n");
		break;
	default:
		fprintf(fp, "(unknown)\n");
		break;
	}
}

/**
 * print arp packet
 * 
 * @param arp arp packet
 * @param fp file descriptor for output
 *
 **/
void print_arp(struct ether_arp *arp, FILE *fp)
{
	static char *hrd[] = {
		"From KA9Q: NET/ROM pseudo.",
		"Ethernet 10/100Mbps.",
		"Experimental Ethernet.",
		"AX.25 Level 2.",
		"PROnet token ring.",
		"Chaosnet.",
		"IEEE 802.2 Ethernet/TR/TB.",
		"ARCnet.",
		"APPLEtalk.",
		"undefine",
		"undefine",
		"undefine",
		"undefine",
		"undefine",
		"undefine",
		"Frame Relay DLCI.",
		"undefine",
		"undefine",
		"undefine",
		"ATM.",
		"undefine",
		"undefine",
		"undefine",
		"Metricom STRIP (new IANA id)."};
	static char *op[] = {
		"undefined",
		"ARP request.",
		"ARP reply.",
		"RARP request.",
		"RARP reply.",
		"undefined",
		"undefined",
		"undefined",
		"InARP request.",
		"InARP reply.",
		"(ATM)ARP NAK."};
	char buf[80];

	fprintf(fp, "##### ARP #####\n");
	fprintf(fp, "arp_hrd=%u", ntohs(arp->arp_hrd));
	if (ntohs(arp->arp_hrd) <= 23)
	{
		fprintf(fp, "(%s),", hrd[ntohs(arp->arp_hrd)]);
	}
	else
	{
		fprintf(fp, "(undefined),");
	}
	fprintf(fp, "arp_pro=%u", ntohs(arp->arp_pro));
	switch (ntohs(arp->arp_pro))
	{
	case ETHERTYPE_IP:
		fprintf(fp, "(IP)\n");
		break;
	case ETHERTYPE_ARP:
		fprintf(fp, "(Address resolution)\n");
		break;
	case ETHERTYPE_REVARP:
		fprintf(fp, "(Reverse ARP)\n");
		break;
	case ETHERTYPE_IPV6:
		fprintf(fp, "(IPv6)\n");
		break;
	default:
		fprintf(fp, "(unknown)\n");
		break;
	}
	fprintf(fp, "arp_hln=%u,", arp->arp_hln);
	fprintf(fp, "arp_pln=%u,", arp->arp_pln);
	fprintf(fp, "arp_op=%u", ntohs(arp->arp_op));
	if (ntohs(arp->arp_op) <= 10)
	{
		fprintf(fp, "(%s)\n", op[ntohs(arp->arp_op)]);
	}
	else
	{
		fprintf(fp, "(undefine)\n");
	}
	fprintf(fp, "arp_sha=%s\n", ether2str(arp->arp_sha, buf, sizeof(buf)));
	fprintf(fp, "arp_spa=%s\n", ip2str(arp->arp_spa, buf, sizeof(buf)));
	fprintf(fp, "arp_tha=%s\n", ether2str(arp->arp_tha, buf, sizeof(buf)));
	fprintf(fp, "arp_tpa=%s\n", ip2str(arp->arp_tpa, buf, sizeof(buf)));
}

/**
 * analyze captured packet. only if it is arp packet, show the details.
 * 
 * @param data captured packet
 * @param size size of captured packet
 * 
 * @return true if the packet is supported, otherwise false.
 **/
bool analyze_arp_packet(u_char *data, int size)
{
	if (size < sizeof(struct ether_header))
	{
		fprintf(stderr, "packet size(%d) < sizeof(struct ether_header)\n", size);
		return false;
	}

	// separate ether_header and body
	struct ether_header *eh = (struct ether_header *)data;
	u_char *body = data + sizeof(struct ether_header);
	int body_size = size - sizeof(struct ether_header);

	if (body_size < sizeof(struct ether_arp))
	{
		fprintf(stderr, "packet body size(%d) < sizeof(struct ether_arp)\n", size);
		return (-1);
	}
	struct ether_arp *arp = (struct ether_arp *)body;

	if (ntohs(eh->ether_type) == ETHERTYPE_ARP)
	{
		// print arp packet
		fprintf(stdout, "\n");
		fprintf(stdout, "Packet[%dbytes]\n", size);
		print_ether_header(eh, stdout);
		print_arp(arp, stdout);
		return true;
	}
	return false;
}


