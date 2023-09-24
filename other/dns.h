#ifndef _DNS_H
#define _DNS_H

#include <stdint.h>
#include <sys/types.h>

#define CHUNCK_SIZE 100 // maximum length of raw data that could be stored into DNS-query
#define MAX_LABEL_SIZE 63

#define PORT 53 // dns port
#define SIZE 1024

//Structure that represents dns header
struct dns_header {
    unsigned short id;       // unique identifier

    unsigned char qr :1;     // query/response flag
    unsigned char opcode :4; // purpose of message
    unsigned char aa :1;     // authoritative answer
    unsigned char tc :1;     // specifies if this message was truncated
    unsigned char rd :1;     // recursion desired
    unsigned char ra :1;     // recursion available
    unsigned char z :3;      // reserved for future use
    unsigned char rcode :4;  // response code

    uint16_t qdcount;        // number of entries in the question section
    uint16_t ancount;        // number of resource records in the answer section
    uint16_t nscount;        // number of name server resource records in the authority records section
    uint16_t arcount;        // number of resource records in the additional records section
};

struct dns_query {
    //represents qname
    size_t label_count;
    char segment[5][64];

    uint16_t qtype;
    uint16_t qclass;
};

//Structure that represents data payload
struct dns_payload {
    uint32_t packet_count;
    uint8_t length;
    unsigned char data[CHUNCK_SIZE];
};

void excerpt_query(unsigned char *buffer, struct dns_query *query);
int check_base_host(char *base_host);

#endif
