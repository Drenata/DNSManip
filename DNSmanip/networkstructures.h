#pragma once

#include <pcap.h>

/* IP address */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

/* IPv4 Header */
typedef struct ip_header {
	u_char ver_ihl;         // Version,4 + headerlength,4
	u_char tos;             // Type of service
	u_short tlen;           // Total length
	u_short identification; // Identification
	u_short flags_fo;       // Flags,3 + fragmentation offset, 13
	u_char ttl;             // Time to live
	u_char proto;           // Protocol
	u_short crc;            // Header checksum
	ip_address saddr;       // Source address
	ip_address daddr;       // Destination address
	u_int op_pad;           // Option + padding
} ip_header;

/* UDP Header */
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
} udp_header;

/* DNS Header (split bytes are reversed due to big-endian small-endian)*/
typedef struct dns_header {
	u_short id;
	u_char recursionDesired : 1;
	u_char truncation : 1;
	u_char authorative : 1;
	u_char opcode : 4;
	u_char isResponse : 1;
	u_char responseCode : 4;
	u_char CheckingDisabled : 1;
	u_char AuthenticatedData : 1;
	u_char Reserved : 1;
	u_char RecursionAvailable : 1;
	u_short QuestionCount;
	u_short AnswerCount;
	u_short NameServerCount;
	u_short AdditionalCount;
} dns_header;