/*
 * soapsniff.c
 *
 *  Created on: Oct 22, 2015
 *      Author: henry
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include <pcap.h>
#include <pcre.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


/* our ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* our prev_package history buffer size */
#define PKT_HISTORY_SIZE 16

int main(int argc, char **argv);
void  handle_sig(int sig);
void handle_packet(const u_char *packet);
pcap_t *open_for_capture(char *device, const char *bpfstr);

char *clean_xml (const char *source);
char *str_replace (char *string, const char *substr, const char *replacement);

void print_ip_hdr(struct iphdr* iph);
void print_tcp_hdr(struct tcphdr *tcph);

int sigQuit = 0;

pcap_t *capture_handle;
char capture_dev[255] = "";
char capture_filter_exp[255] = "";
uint8_t debug_mode = 0;

pcre *re;
pcre_extra *ree;

struct pPackageT
{
	u_int ack_nr;
	u_int32_t s_ip;
	u_int32_t d_ip;
	u_int32_t payload_size;
	char payload[(1500 * PKT_HISTORY_SIZE) + 1];
} prev_package;

int main(int argc, char **argv)
{
	int c;

	const char *pcreErrorStr;
	int pcreErrorOffset;

	if (argc == 1)
	{
		fprintf(stdout, "Usage: %s [ -i interface ] [ -d ] [ -f filter ]\n", argv[0]);
		return EXIT_FAILURE;
	}

	while ((c = getopt (argc, argv, "di:f:")) != -1)
	{
		switch (c)
		{
			case 'd':
				debug_mode += 1;
				break;
			case 'i':
				strncpy(capture_dev, optarg, 255);
				break;
			case 'f':
				strncpy(capture_filter_exp, optarg, 255);
				break;
			case '?':
				if (optopt == 'c')
				{
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				}
				else if (isprint (optopt))
				{
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				}
				else
				{
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				}
				return EXIT_FAILURE;
		}
	}

	if (debug_mode >= 1)
	{
		fprintf(stderr, "[DEBUG] Parsed options:\n");
		fprintf(stderr, "	debug_mode = %d\n", debug_mode);
		fprintf(stderr, "	capture_dev = %s\n", capture_dev);
		fprintf(stderr, "	capture_filter_exp = %s\n", capture_filter_exp);
		fprintf(stderr, "-----------------------\n");
	}

	if ((capture_handle = open_for_capture(capture_dev, capture_filter_exp)) == NULL)
	{
		return EXIT_FAILURE;
	}

	char *regex = "(\\<\\?xml[^\\>]+\\>\\s*\\<SOAP-ENV:Envelope[^\\>]+>.+?\\</SOAP-ENV:Envelope[^\\>]*>)";
	re = pcre_compile(regex, (PCRE_CASELESS | PCRE_DOTALL), &pcreErrorStr, &pcreErrorOffset, NULL);

	if(re == NULL) {
		fprintf(stderr, "Couldn't compile '%s': %s\n", regex, pcreErrorStr);
		return EXIT_FAILURE;
	}

	ree = pcre_study(re, 0, &pcreErrorStr);

	if(pcreErrorStr != NULL) {
		fprintf(stderr, "Couldn't study '%s': %s\n", regex, pcreErrorStr);
		return EXIT_FAILURE;
	}

	struct pcap_pkthdr pkt_header;	/* The header that pcap gives us */
	memset(&prev_package, 0, sizeof(prev_package));

	signal(SIGINT, handle_sig);

	while (!sigQuit)
	{
		const u_char *packet = pcap_next(capture_handle, &pkt_header);

		if (!packet)
		{
			if (debug_mode >= 3)
			{
				fprintf(stderr, "-- Skipping non packet\n");
			}

			continue;
		}

		handle_packet(packet);
	}

	/* close the capture */
	pcap_close(capture_handle);

	// Free up the regular expression.
	pcre_free(re);

	// Free up the EXTRA PCRE value (may be NULL at this point)
	if(ree != NULL)
	{
		pcre_free(ree);
	}

	return EXIT_SUCCESS;
}

void  handle_sig(int sig)
{
	switch (sig)
	{
		case SIGINT:
		case SIGSEGV:
			sigQuit = 1;
			break;
	}
}

void handle_packet(const u_char *packet)
{
	int i;
	uint16_t pkt_size, payload_size;

	struct iphdr *ip;				/* The IP header */
	struct tcphdr *tcp;				/* The TCP header */
	char *payload;					/* Packet payload */

	int vector_size = 18;
	int substrvec[vector_size];
	const char *submatchstr;

	ip = (struct iphdr*)(packet + SIZE_ETHERNET);

	if (ip->protocol != IPPROTO_TCP)
	{
		/* We are only interested in TCP traffic */

		if (debug_mode >= 3)
		{
			fprintf(stderr, "-- Skipping non TCP packet\n");
		}

		return;
	}

	if ((ip->ihl * 4) < 20)
	{
		if (debug_mode >= 3)
		{
			fprintf(stderr, "-- Skipping Invalid IP header\n");
		}

		return;
	}

	tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + (ip->ihl * 4));

	if ((tcp->doff * 4) < 20)
	{
		if (debug_mode >= 3)
		{
			fprintf(stderr, "-- Skipping Invalid TCP header\n");
		}

		return;
	}

	if (debug_mode >= 4)
	{
		print_ip_hdr(ip);
		print_tcp_hdr(tcp);
	}

	pkt_size = ntohs(ip->tot_len);
	payload_size = pkt_size - ((ip->ihl * 4) + (tcp->doff * 4));
	payload = (char *)(packet + SIZE_ETHERNET + (ip->ihl * 4) + (tcp->doff * 4));

	if (ntohl(tcp->ack_seq) == prev_package.ack_nr &&
			ip->saddr == prev_package.s_ip && ip->daddr == prev_package.d_ip)
	{
		if ((prev_package.payload_size + payload_size) > (1500 * PKT_HISTORY_SIZE) + 1)
		{
			if (debug_mode >= 3)
			{
				fprintf(stderr, "-- Dropping packet due to full packet buffer\n");
			}

			return;
		}

		prev_package.payload_size += payload_size;
		strncat(prev_package.payload, payload, payload_size);

		payload = prev_package.payload;
		payload_size = prev_package.payload_size;
	}
	else
	{
		if (prev_package.payload_size > 0)
		{
			memset(&prev_package, 0x00, sizeof(struct pPackageT));
		}

		prev_package.ack_nr = ntohl(tcp->ack_seq);
		prev_package.s_ip = ip->saddr;
		prev_package.d_ip = ip->daddr;

		prev_package.payload_size += payload_size;
		strncat(prev_package.payload, payload, payload_size);

//		if (pkt_size >= 1500)
//		{
//			if (debug_mode >= 3)
//			{
//				fprintf(stderr, "-- Skipping due to 1500bytes\n");
//			}
//
//			return;
//		}
	}

	if (debug_mode >= 5)
	{
	    fprintf(stderr, "Payload (%u): \n", payload_size);

	    for (i = 0; i < payload_size; i++)
	    {
	    	if (isprint(payload[i]) || payload[i] == 10)
	    	{
	    		fprintf(stderr, "%c", payload[i]);
	    	}
	    	else
	    	{
	    		fprintf(stderr, ".");
	    	}
	    }

	    fprintf(stderr, "\n--\n");
	}

	int pcre_match = pcre_exec(re, ree, payload, payload_size, 0, 0, substrvec, vector_size);

	if (debug_mode)
	{
		fprintf(stderr, ">> pcre: %d\n", pcre_match);
	}

	if(pcre_match < 0)
	{
//		switch (pcre_match)
//		{
//			case PCRE_ERROR_NOMATCH:
//			case PCRE_ERROR_NULL:
//			case PCRE_ERROR_BADOPTION:
//			case PCRE_ERROR_BADMAGIC:
//			case PCRE_ERROR_UNKNOWN_NODE:
//			case PCRE_ERROR_NOMEMORY:
//				return;
//				break;
//		}
		return;
	}

	if (pcre_match == 0)
	{
		if (debug_mode >= 3)
		{
			fprintf(stderr, "PCRE Matched but too many substrings returned\n");
		}

		pcre_match = (vector_size / 3);
	}

	if (pcre_match >= 2)
	{
		pcre_get_substring(payload, substrvec, pcre_match, 1, &(submatchstr));
		char *clean_str = clean_xml(submatchstr);

		fprintf(stdout, "%s\n", clean_str);

		// Free up the stuff
		free (clean_str);

		pcre_free_substring(submatchstr);
		memset(&prev_package, 0x00, sizeof(struct pPackageT));
	}
}

pcap_t *open_for_capture(char *device, const char *bpfstr)
{
	pcap_t* pd;

	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;		/* The IP of our sniffing device */

	struct bpf_program bpf;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (!*device)
	{
		if ((device = pcap_lookupdev(errbuf)) == NULL)
		{
			fprintf(stderr, "Couldn't open default capture device.\n");
			return NULL;
		}

		if (debug_mode > 0)
		{
			fprintf(stderr, "[DEBUG] Capture_dev = %s\n", device);
		}
	}

	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
	{
		net = PCAP_NETMASK_UNKNOWN;
	}

	/* Open the session in promiscuous mode */
	if ((pd = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		return NULL;
	}

	if (*bpfstr)
	{
		/* Compile and apply the filter */
		if (pcap_compile(pd, &bpf, bpfstr, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", capture_filter_exp, pcap_geterr(pd));
			return NULL;
		}

		if (pcap_setfilter(pd, &bpf) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", bpfstr, pcap_geterr(pd));
			return NULL;
		}

		/* free willy */

		/*
		 * As the doc says:
		 *
		 * pcap_freecode() is used to free up allocated memory pointed to by a bpf_program struct
		 * generated by pcap_compile() when that BPF program is no longer needed, for example after
		 * it has been made the filter program for a pcap structure by a call to pcap_setfilter().
		 *
		 * Since we set the filter, we shoudl be OK to free it now.
		 * ! Keep your fingers crossed !
		 */
		pcap_freecode(&bpf);
	}

	if (pcap_datalink(pd) != DLT_EN10MB)
	{
		fprintf(stderr, "I only support capturing on physical devices\n");
		return NULL;
	}

	return pd;
}

char *clean_xml (const char *source)
{
	char *newstr = strdup(source);
	
	newstr = str_replace(newstr, "\n", "");
	//newstr = str_replace(newstr, ">  ", ">");
	//newstr = str_replace(newstr, " <", "<");
	newstr = str_replace(newstr, "  ", "");

	return newstr;
}

char *str_replace (char *string, const char *substr, const char *replacement)
{
	char *tok = NULL;
	char *newstr = NULL;
	char *oldstr = NULL;

	/* if either substr or replacement is NULL, duplicate string a let caller handle it */

	if (substr == NULL || replacement == NULL)
	{
		return strdup (string);
	}

	newstr = strdup(string);

	while ((tok = strstr(newstr, substr)))
	{
		oldstr = newstr;
		newstr = malloc(strlen(oldstr) - strlen(substr) + strlen(replacement) + 1);

		/* If failed to alloc mem, free old string and return NULL */
		if (newstr == NULL)
		{
			free (oldstr);
			return NULL;
		}

		memcpy(newstr, oldstr, tok - oldstr);
		memcpy(newstr + (tok - oldstr), replacement, strlen(replacement));
		memcpy(newstr + (tok - oldstr) + strlen(replacement), tok + strlen(substr), strlen(oldstr) - strlen(substr) - (tok - oldstr));
		memset(newstr + strlen(oldstr) - strlen(substr) + strlen(replacement) , 0, 1);

		free (oldstr);
	}

	free (string);
	return newstr;
}

void print_ip_hdr(struct iphdr* iph)
{
	struct sockaddr_in source,dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(stderr , "\n");
	fprintf(stderr , "IP Header\n");
	fprintf(stderr , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(stderr , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(stderr , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(stderr , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(stderr , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(stderr , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	fprintf(stderr , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	fprintf(stderr , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(stderr , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(stderr , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(stderr , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(stderr , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(stderr , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void print_tcp_hdr(struct tcphdr *tcph)
{
	fprintf(stderr , "\n");
	fprintf(stderr , "TCP Header\n");
	fprintf(stderr , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(stderr , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(stderr , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(stderr , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(stderr , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(stderr , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(stderr , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(stderr , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(stderr , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(stderr , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(stderr , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(stderr , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(stderr , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(stderr , "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(stderr , "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(stderr , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(stderr , "\n");
	fprintf(stderr , "                        DATA Dump                         ");
	fprintf(stderr , "\n");
}
