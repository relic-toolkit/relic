#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include <pthread.h>

#include "relic.h"
#include "params.h"

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int cp_pbpsi_inth(bn_t z[], int *len, bn_t sk, g2_t d[], bn_t x[], int m,
		uint8_t t[][RLC_MD_LEN], g1_t u[], int n) {
	int j, k, result = RLC_OK;
	gt_t e;
    uint8_t h[RLC_MD_LEN], buffer[12 * RLC_PC_BYTES];

	gt_null(e);

	RLC_TRY {
		gt_new(e);

		*len = 0;
		if (m > 0) {
			for (k = 0; k < m; k++) {
				for (j = 0; j < n; j++) {
					pc_map(e, u[j], d[k + 1]);
                    gt_write_bin(buffer, 12 * RLC_PC_BYTES, e, 0);
                    md_map(h, buffer, sizeof(buffer));
					if (memcmp(h, t[j], RLC_MD_LEN) == RLC_EQ && !gt_is_unity(e)) {
						bn_copy(z[*len], x[k]);
						(*len)++;
					}
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		gt_free(e);
	}
	return result;
}

void *socketThread(void *arg) {
    uint8_t *ptr, buffer[2 * RLC_PC_BYTES + 1 + (M + 1) * (4 * RLC_PC_BYTES + 1)];
    bn_t q, r, x[M];
    g1_t ss, u[N];
    g2_t d[M + 1], s[M + 1];
    uint8_t t[N][RLC_MD_LEN];
    int len = 0;

    bn_null(q);
    bn_null(r);
    g1_null(ss);

    bn_new(q);
    bn_new(r);
    g1_new(ss);
    for (int i = 0; i < N; i++) {
        g1_null(u[i]);
        g1_new(u[i]);
    }
    for (int i = 0; i < M; i++) {
        bn_null(x[i]);
		g2_null(d[i]);
        g2_null(s[i]);
        bn_new(x[i]);
		g2_new(d[i]);
        g2_new(s[i]);
    }
	g2_null(d[M]);
    g2_new(d[M]);
    g2_null(s[M]);
    g2_new(s[M]);

    if (core_init() != RLC_OK) {
		goto end;
	}

    if (pc_param_set_any() != RLC_OK) {
		goto end;
    }

    pc_get_ord(q);
    bn_set_dig(x[0], 1);
    for (int j = 1; j < M; j++) {
        bn_rand_mod(x[j], q);
    }

    cp_pbpsi_gen(q, ss, s, M);

    int newSocket = *((int *)arg);
    recv(newSocket, buffer, sizeof(buffer), 0);

    g1_read_bin(ss, buffer, 2 * RLC_PC_BYTES + 1);

    ptr = buffer + 2 * RLC_PC_BYTES + 1;
    for (int i = 0; i <= M; i++) {
        g2_read_bin(s[i], ptr,  4 * RLC_PC_BYTES + 1);
        ptr += 4 * RLC_PC_BYTES + 1;
    }

    cp_pbpsi_ask(d, r, x, s, M);
    g2_write_bin(buffer, 4 * RLC_PC_BYTES + 1, d[0], 0);
	// Send message to the client socket
    send(newSocket, buffer, 4 * RLC_PC_BYTES + 1, 0);

    recv(newSocket, buffer, N * (RLC_MD_LEN + 2 * RLC_PC_BYTES + 1), 0);

    ptr = buffer;
    for (int i = 0; i < N; i++) {
        memcpy(t[i], ptr, RLC_MD_LEN);
        ptr += RLC_MD_LEN;
        g1_read_bin(u[i], ptr, 2 * RLC_PC_BYTES + 1);
        ptr += 2 * RLC_PC_BYTES + 1;
    }

    cp_pbpsi_inth(x, &len, q, d, x, M, t, u, N);
    printf("%d\n", len);

    printf("Exit socketThread \n");

end:
    close(newSocket);

    bn_free(q);
    bn_free(r);
    g1_free(ss);
    for (int i = 0; i <= M; i++) {
    	g2_free(d[i]);
        g2_free(s[i]);
    }
    core_clean();

    pthread_exit(NULL);
}

int main(){
    int serverSocket, newSocket;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;

    //Create the socket.
    serverSocket = socket(PF_INET, SOCK_STREAM, 0);

    // Configure settings of the server address struct
    // Address family = Internet
    serverAddr.sin_family = AF_INET;

    //Set port number, using htons function to use proper byte order
    serverAddr.sin_port = htons(1337);

    //Set IP address to localhost
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    //Set all bits of the padding field to 0
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    //Bind the address struct to the socket
    bind(serverSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

    //Listen on the socket, with 40 max connection requests queued
    if(listen(serverSocket, 50) == 0) {
        printf("Listening\n");
    } else {
        printf("Error\n");
    }

    pthread_t tid[60];
    int i = 0;
    while (1) {
        //Accept call creates a new socket for the incoming connection
        addr_size = sizeof serverStorage;
        newSocket = accept(serverSocket, (struct sockaddr *) &serverStorage, &addr_size);

        //for each client request creates a thread and assign the client request to it to process
        //so the main thread can entertain next request
        if( pthread_create(&tid[i++], NULL, socketThread, &newSocket) != 0 ) {
            printf("Failed to create thread\n");
        }

        if (i >= 50) {
            i = 0;
            while(i < 50) {
                pthread_join(tid[i++],NULL);
            }
            i = 0;
        }
    }

    return 0;
}
