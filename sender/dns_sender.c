#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../other/base32.h"
#include "../other/dns.h"
#include "../other/error.h"
#include "dns_sender_events.h"

// Packet flag values
#define FILEPATH_PACKET 100
#define PACKET 101

/**
 * @brief Gets ip from /etc/resolv.conf
 */
char* get_default_dns() {
    FILE *fp;
    char str[SIZE];
    char *dns;

    fp = fopen("/etc/resolv.conf", "r");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open a file : %d\n", FILE_ERROR);
        exit(FILE_ERROR);
    }

    while (fgets(str, SIZE, fp)) {
        if (strncmp(str , "nameserver" , 10) == 0) {
            dns = strtok(str, " ");
            dns = strtok(NULL, " ");
            break;
        }
    }
    return dns;
}

/**
 * @brief Sends data
 *
 * @param encoded_buf buffer with encoded data
 * @param dst_filepath destination file path
 * @param base_host base host
 * @param source IPv4 client address
 * @param chunkId Id of the data chunk
 */
int send_chunck(unsigned char *encoded_buffer, int encoded_length, struct in_addr *ip, char *base_host, int flag) {
    unsigned char buffer[SIZE];
    unsigned char response[SIZE];
    memset(buffer, '\0', SIZE);

    struct dns_header *header = (struct dns_header*) buffer;

    if (flag == FILEPATH_PACKET) {
        header->id = htons(888); // Packet contains ONLY dst_filepath
    } else {
        header->id = htons(666); // Packet contains data, that server need to save
    }
    header->qr     = 0;
    header->opcode = 0;
    header->aa     = 0;
    header->tc     = 0;
    header->rd     = 1;
    header->ra     = 0;
    header->z      = 0;
    header->rcode  = 0;

    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;

    unsigned char *buffer_ptr = buffer + sizeof(struct dns_header);

    int labels_count;
    // gets count of labels
    if ((encoded_length % MAX_LABEL_SIZE) == 0) {
        labels_count = encoded_length / MAX_LABEL_SIZE;
    } else {
        labels_count = (encoded_length / MAX_LABEL_SIZE) + 1;
    }

    // separates encoded data into labels
    for (int i = 0; i < labels_count; i++) {
        int start = i * MAX_LABEL_SIZE;
        int count;
        if (start + MAX_LABEL_SIZE <= encoded_length) {
            count = MAX_LABEL_SIZE;
        } else {
            count = encoded_length - start;
        }
        *buffer_ptr = (unsigned char)count;
        memcpy(buffer_ptr + 1, encoded_buffer + start, count);
        count++;
        buffer_ptr += count;
    }

    // example.com
    // -> 06example03com00
    int stop = 0;
    for (int i = 0 ; i < strlen((char*)base_host) + 1; i++) {
        if (base_host[i] == '.' || base_host[i] == '\0') {
            *buffer_ptr++ = i - stop;
            while (stop < i) {
                *buffer_ptr++ = base_host[stop];
                stop++;
            }
            stop++;
        }
    }
    *buffer_ptr++;
    *buffer_ptr = '\0';

    *((uint16_t*)(buffer_ptr)) = htons(1); // sets qtype
    *((uint16_t*)(buffer_ptr + 2)) = htons(1); // sets qclass
    int buffer_size = buffer_ptr + 4 - buffer; // +4 because of qtype and qclass

    struct sockaddr_in server_addr = {0};
    socklen_t server_addrlen = sizeof server_addr;

    int server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_sock == -1) {
        perror("Socket error");
        exit(SOCKET_ERROR);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr = *ip;

    // send a packet
    if (sendto(server_sock, buffer, buffer_size, MSG_CONFIRM, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in)) == -1) {
        fprintf(stderr, "Send error : %d\n", SEND_ERROR);
        exit(SEND_ERROR);
    }

    // get response from the server if it has received a packet
    int received;
    if ((received = recvfrom(server_sock, response, sizeof response, MSG_WAITALL, (struct sockaddr*)&server_addr, &server_addrlen)) == -1) {
        fprintf(stderr, "Recevie error : %d\n", RECEIVE_ERROR);
        exit(RECEIVE_ERROR);
    }

    return 0;
}

int main(int argc, char const *argv[]) {
    struct in_addr ip;
    FILE *fp;
    char *base_host;
    char *dst_filepath;
    char *src_filepath;

    int chunk_id = 0; // id of data chunk

    //  Parse arguments
    if (argc == 6) {
        if (strcmp(argv[1], "-u") == 0) {
            if (!inet_aton((char*)argv[2], &ip)) {
                fprintf(stderr, "Wrong UPSTREAM_DNS_IP : %d\n", WRONG_PARAM);
                exit(WRONG_PARAM);
            }
        } else {
            fprintf(stderr, "Wrong parameter : %d\n", WRONG_PARAM);
            exit(WRONG_PARAM);
        }

        src_filepath = (char*)argv[5];
        fp = fopen(src_filepath, "rb");
        if (fp == NULL) {
            fprintf(stderr, "Unable to open a file : %d\n", FILE_ERROR);
            exit(FILE_ERROR);
        }
        base_host = (char*)argv[3];
        dst_filepath = (char*)argv[4];
    } else if (argc == 4) {
        if (!inet_aton(get_default_dns(), &ip)) {
            fprintf(stderr, "Wrong UPSTREAM_DNS_IP (from /etc/resolv.conf) : %d\n", WRONG_PARAM);
            exit(WRONG_PARAM);
        }

        base_host = (char*)argv[1];
        dst_filepath = (char*)argv[2];
        src_filepath = (char*)argv[3];
        fp = fopen(src_filepath, "rb");
        if (fp == NULL) {
            fprintf(stderr, "Unable to open a file : %d\n", FILE_ERROR);
            exit(FILE_ERROR);
        }
    } else if (argc == 3) {
        if (!inet_aton(get_default_dns(), &ip)) {
            fprintf(stderr, "Wrong UPSTREAM_DNS_IP (from /etc/resolv.conf) : %d\n", WRONG_PARAM);
            exit(WRONG_PARAM);
        }
        base_host = (char*)argv[1];
        dst_filepath = (char*)argv[2];
        src_filepath = 0;
        fp = stdin;
    }

    // checks if base host is valid
    if (check_base_host(base_host)) {
        fprintf(stderr, "Wrong BASE_HOST : %d\n", WRONG_PARAM);
        exit(WRONG_PARAM);
    }

    struct dns_payload payload;
    payload.packet_count = 0;

    // send dst_filepath
    unsigned char filepath[SIZE];
    memset(filepath, '\0', SIZE);
    int filepath_length = base32_encode((unsigned char*)dst_filepath, strlen(dst_filepath), (unsigned char*)filepath, SIZE);
    filepath[filepath_length] = '\0';
    send_chunck(filepath, filepath_length, &ip, base_host, FILEPATH_PACKET);

    unsigned char encoded_buffer[SIZE];

    dns_sender__on_transfer_init(&ip);

    // main loop
    while (!feof(fp)) {
        // read from input file raw data whose length <= CHUNCK_SIZE
        payload.length = (unsigned char)fread(payload.data, 1, CHUNCK_SIZE, fp);
        if (ferror(fp) && payload.length != CHUNCK_SIZE) {
            fprintf(stderr, "Unable to read a file : %d\n", FILE_ERROR);
            exit(FILE_ERROR);
        }

        // encode data
        int encoded_length = base32_encode((unsigned char*)&payload, sizeof(struct dns_payload) + payload.length - CHUNCK_SIZE, (unsigned char*)encoded_buffer, SIZE);
        encoded_buffer[encoded_length] = '\0';
        dns_sender__on_chunk_encoded(dst_filepath , chunk_id, encoded_buffer);
        // send data packet
        send_chunck(encoded_buffer, encoded_length, &ip, base_host, PACKET);

        dns_sender__on_chunk_sent(&ip, dst_filepath, chunk_id, payload.length);

        chunk_id++;
        payload.packet_count++;
    }
    fseek(fp, 0L, SEEK_END);
    int size = ftell(fp);
    dns_sender__on_transfer_completed(dst_filepath, size);
    fclose(fp);

    return 0;
}
