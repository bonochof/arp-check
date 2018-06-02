#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include "librawsocket.h"
#include "libarp.h"

void hexdump(u_char* data, int size);

int main(int argc, char *argv[])
{
	int soc = -1;
	int size = 0;
	u_char buf[65535];

	if (argc <= 1)
	{
		fprintf(stderr, "Usage: arpcheck device_name\n");
		return (1);
	}

	// initialize raw socket
	if ((soc = init_raw_socket(argv[1])) == -1)
	{
		fprintf(stderr, "ERROR: cannot initialize device: %s\n", argv[1]);
		return (-1);
	}

	// capture any arp packets
	while (true)
	{
		if ((size = read(soc, buf, sizeof(buf))) <= 0)
		{
			perror("read buf");
		}
		else
		{
			// hexdump(buf, size);
			analyze_arp_packet(buf, size);
		}
	}
	close(soc);
	return (0);
}


/**
 * hexdump - dump binary data with hex format
 *
 * @param data dump target data
 * @param size size of dump target data
 *
 */
void hexdump(u_char* data, int size) {

	char buf[16];

	for (int i = 0; i <= size; i++) {

		if ( i % 16 == 0 ) {
			bzero(buf, 16);	// init buffer
			printf("%06X  ", i*16);	// print base address
		}

		printf("%02X ", data[i]);
		buf[i%16] = data[i];

		if ( i % 16 == 15 || i == size - 1 ) {
			for ( int k=0; k<15-i%16; k++ ) {
				printf("   ");
			}
			printf("  ");
			for ( int j=0; j<16; j++ ) {
				char ch = buf[j] & 0xFF;
				if (32 < ch && ch < 127) {
					printf("%c", ch);
				}
				else {
					printf("･");
				}
			}
			printf("\n");
		}
	}
	printf("\n");
}

