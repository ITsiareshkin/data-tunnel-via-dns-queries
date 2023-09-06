#include "dns.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Excerpt dns-query
 *
 * @param buffer buffer with dns-query
 * @param query dns-query structure pointer
 */
void excerpt_query(unsigned char *buffer, struct dns_query *query) {
    unsigned char *query_ptr = buffer + sizeof(struct dns_header);
    query->label_count = 0;

    unsigned char label_size;
    while ((label_size = *((unsigned char *)query_ptr))) {
        if (label_size > MAX_LABEL_SIZE) {
            // MALFORMED_DNS_REQUEST
            return;
        }

        strncpy(query->segment[query->label_count], (char *)(query_ptr + 1), label_size);
        query->segment[query->label_count][label_size] = '\0';
        query->label_count++;
        query_ptr += label_size + 1;
    }
}

/**
 * @brief Checks if base_host is correct
 *
 * @param base_host base host
 */
int check_base_host(char *base_host) {
    int dot = 0;
    for (int i = 0; i < strlen(base_host); i++) {
        if (base_host[i] == '.') {
            if (i == 0 || i == strlen(base_host) - 1) {
                return 1;
            }
            dot++;
        }
    }
    if (dot != 1) {
        return 1;
    }
    return 0;
}
