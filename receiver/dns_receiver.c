#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "../other/base32.h"
#include "../other/dns.h"
#include "../other/error.h"
#include "dns_receiver_events.h"

#define SIZE 1024 // Size of buffer, no matter

// Packet values
#define LAST_PACKET 100
#define NOT_LAST_PACKET 101
#define WRONG_PACKET 102

/**
 * @brief Writes data
 *
 * @param encoded_buf buffer with encoded data
 * @param dst_filepath destination file path
 * @param base_host base host
 * @param source IPv4 client address
 * @param chunkId Id of the data chunk
 */
int write_data(unsigned char *encoded_buf, char *dst_filepath, char *base_host, struct in_addr *source, int chunkId) {
    unsigned char decoded_buf[512];
    dns_receiver__on_query_parsed(dst_filepath, encoded_buf);
    // decode data
    base32_decode(encoded_buf, decoded_buf, 512);
    struct dns_payload *payload = (struct dns_payload *)decoded_buf;

    // open a binary file in append mode for reading or updating at the end of the file
    FILE *fp = fopen(dst_filepath, "a+b");

    fseek(fp, CHUNCK_SIZE * payload->packet_count, 0);
    fwrite(payload->data, 1, payload->length, fp);
    fclose(fp);

    dns_receiver__on_chunk_received(source, dst_filepath, chunkId, payload->length);
    if (payload->length < CHUNCK_SIZE) {
        // last packet;
        return LAST_PACKET;
    } else {
        // not last packet
        return NOT_LAST_PACKET;
    }
}


int main(int argc, char const *argv[]) {
    char *base_host = (char*)argv[1];
    char *dst_filepath = (char*)argv[2];

    int filpath_const_len = strlen(dst_filepath);

    int clear_file = 0; // flag that indicates whether the file should be cleared
    int chunk_id = 0; // id of data chunk
    FILE *fp;

    // checks if base host is valid
    if (check_base_host(base_host)) {
        fprintf(stderr, "Wrong BASE_HOST : %d\n", WRONG_PARAM);
        exit(WRONG_PARAM);
    }
    // checks if dir exists
    struct stat stats;
    if (stat(dst_filepath, &stats) == -1) {
        if (mkdir(dst_filepath, 0777) != 0) {
            fprintf(stderr, "Dir making error : %d\n", DIR_MAKE_ERROR);
            exit(DIR_MAKE_ERROR);
        }
    }

    unsigned char buffer[SIZE];

    int server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_sock == -1) {
        fprintf(stderr, "Socket error : %d\n", SOCKET_ERROR);
        exit(SOCKET_ERROR);
    }

    struct sockaddr_in server_addr = {0};
    struct sockaddr_in client_addr = {0};
    socklen_t server_addrlen = sizeof server_addr;
    socklen_t client_addrlen = sizeof client_addr;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*) &server_addr, sizeof server_addr) == -1) {
        fprintf(stderr, "Bind error : %d\n",BIND_ERROR);
        exit(BIND_ERROR);
    }

    // main loop
    while (1) {
        memset(buffer, '\0', SIZE);
        int received = 0;
        // receive a packet
        if ((received = recvfrom(server_sock, (char*)buffer, SIZE, MSG_WAITALL, (struct sockaddr*)&client_addr, &client_addrlen)) == -1) {
            fprintf(stderr, "Recevie error : %d\n", RECEIVE_ERROR);
            exit(RECEIVE_ERROR);
        }

        struct dns_header *header = (struct dns_header*)buffer;
        struct dns_query query;

        // excerpts a dns-query
        excerpt_query(buffer, &query);

        unsigned char encoded_buf[300] = {0};
        int i = 0;
        for (i = 0; i < query.label_count - 2; i++) {
            strncat((char*)encoded_buf, query.segment[i], 1024);
        }

        unsigned char host[300] = {0};
        strncat((char*)host, query.segment[i], 1024);
        strcat((char*)host, ".");
        strncat((char*)host, query.segment[i+1], 1024);

        // check if base_host is correct
        if (strncmp(base_host, host, strlen(base_host)) == 0) {
            // Packet contains ONLY dst_filepath
            if (ntohs(header->id) == 888) {
                unsigned char decoded_buf[512] = {0};
                base32_decode(encoded_buf, decoded_buf, 512);
                if (strncmp(decoded_buf, ".", 1) == 0) { // ./dir/file -> /dir/file
                    memmove(decoded_buf, decoded_buf + 1, strlen(decoded_buf));
                } else if (strncmp(decoded_buf, "/", 1) == 0) { // /dir/file -> error
                    fprintf(stderr, "Wrong DST filepath name : %d\n", WRONG_DST_FILEPATH);
                } else { // dir/file -> /dir/file
                    memmove(decoded_buf + 1, decoded_buf, strlen(decoded_buf));
                    memset(decoded_buf, '/', 1);
                }
                //strcat with dst_filepath: ./filepath/dir/file
                strcat((char*)dst_filepath, (char*)decoded_buf);
                dns_receiver__on_transfer_init(&(client_addr.sin_addr));
            }

            if (clear_file == 0) {
                fp = fopen(dst_filepath, "wb"); // make new bin file, or clean already existed one
                if (fp == NULL) {
                    fprintf(stderr, "Unable to open a file : %d\n", FILE_ERROR);
                }
            }

            // response flag
            header->qr = 1;
            // send a response
            if (sendto(server_sock, buffer, received, 0, (struct sockaddr*)&client_addr, sizeof(client_addr)) == -1) {
                fprintf(stderr, "Send error : %d\n", SEND_ERROR);
                exit(SEND_ERROR);
            }

            // Packet contains data, that server need to save
            if (ntohs(header->id) == 666) {
                int result = write_data(encoded_buf, (char*)dst_filepath, base_host, &(client_addr.sin_addr), chunk_id);
                if (result == LAST_PACKET) {
                    chunk_id++;
                    clear_file = 0;
                    fseek(fp, 0L, SEEK_END);
                    int size = ftell(fp);
                    dns_receiver__on_transfer_completed((char*)dst_filepath, size);
                    dst_filepath[filpath_const_len] = '\0';
                    fclose(fp);
                } else if (result == NOT_LAST_PACKET) {
                    chunk_id++;
                    clear_file = 1;
                } else if (result == WRONG_PACKET) {
                    dst_filepath[filpath_const_len] = '\0';
                    clear_file = 1;
                }
            }
        }
    }
    return 0;
}
