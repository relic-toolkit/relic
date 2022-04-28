#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <pthread.h>

#include "relic.h"
#include "params.h"

#define INSTANCES 1

void *clientThread(void *arg) {
    printf("In thread\n");
    int clientSocket;
    struct sockaddr_in serverAddr;
    socklen_t addr_size;

    uint8_t buffer[2 * RLC_PC_BYTES + 1 + (M + 1) * (4 * RLC_PC_BYTES + 1)];
    uint8_t *ptr, tmp[12 * RLC_PC_BYTES];
    bn_t q, y[N];
    g1_t ss, u[N];
    g2_t d, s[M + 1];
    gt_t t[N];

    // Create the socket.
    clientSocket = socket(PF_INET, SOCK_STREAM, 0);

    //Configure settings of the server address
    // Address family is Internet
    serverAddr.sin_family = AF_INET;

    //Set port number, using htons function
    serverAddr.sin_port = htons(1337);

    //Set IP address to localhost
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    //Connect the socket to the server using the address
    addr_size = sizeof serverAddr;
    connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);

    bn_null(q);
    bn_new(q);
    g1_null(ss);
    g1_new(ss);
    g2_null(d);
    g2_new(d);
    for (int i = 0; i < N; i++) {
        bn_null(y[i]);
        g1_null(u[i]);
        gt_null(t[i]);
        bn_new(y[i]);
        g1_new(t[i]);
        gt_new(t[i]);
    }
    for (int i = 0; i <= M; i++) {
        g2_null(s[i]);
        g2_new(s[i]);
    }

    if (core_init() != RLC_OK) {
		goto end;
	}

    if (pc_param_set_any() != RLC_OK) {
		goto end;
    }

    cp_pbpsi_gen(q, ss, s, M);

    pc_get_ord(q);
    bn_set_dig(y[0], 1);
    for (int j = 1; j < N; j++) {
        bn_rand_mod(y[j], q);
    }

    g1_write_bin(buffer, 2 * RLC_PC_BYTES + 1, ss, 0);
    ptr = buffer + 2 * RLC_PC_BYTES + 1;
    for (int i = 0; i <= M; i++) {
        g2_write_bin(ptr, 4 * RLC_PC_BYTES + 1, s[i], 0);
        ptr += 4 * RLC_PC_BYTES + 1;
    }

    if (send(clientSocket, buffer, sizeof(buffer), 0) < 0) {
        printf("Send failed\n");
    }

    bench_reset();
    bench_before();

    //Read the message from the server into the buffer
    if (recv(clientSocket, buffer, 4 * RLC_PC_BYTES + 1, 0) < 0) {
       printf("Receive failed\n");
    }
    g2_read_bin(d, buffer, 4 * RLC_PC_BYTES + 1);

    cp_pbpsi_ans(t, u, ss, d, y, N);

    ptr = buffer;
    for (int i = 0; i < N; i++) {
        gt_write_bin(tmp, 12 * RLC_PC_BYTES, t[i], 0);
        md_map(ptr, tmp, 12 * RLC_PC_BYTES);
        ptr += RLC_MD_LEN;
        g1_write_bin(ptr, 2 * RLC_PC_BYTES + 1, u[i], 0);
        ptr += 2 * RLC_PC_BYTES + 1;
    }

    if (send(clientSocket, buffer, ptr - buffer, 0) < 0) {
        printf("Send failed\n");
    }

    bench_after();
    bench_compute(1);
    printf("Sender: ");
    bench_print();

end:
    close(clientSocket);

    bn_free(q);
    g1_free(ss);
    for (int i = 0; i < N; i++) {
        bn_free(y[i]);
        g1_free(u[i]);
        gt_free(t[i]);
    }
    for (int i = 0; i <= M; i++) {
        g2_free(s[i]);
    }
    core_clean();

    pthread_exit(NULL);
}

int main () {
    pthread_t tid[INSTANCES + 1];

    for (int i = 0; i < INSTANCES; i++) {
        if (pthread_create(&tid[i], NULL, clientThread, NULL) != 0) {
            printf("Failed to create thread\n");
        }
    }

    for (int i = 0; i < INSTANCES; i++) {
        pthread_join(tid[i], NULL);
    }

    return 0;
}
