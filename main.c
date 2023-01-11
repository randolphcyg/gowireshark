#include "lib.h"
#include "online.h"

#include <getopt.h>

extern capture_file *cf;
//extern static output_fields_t *output_fields = NULL;

int main(int argc,  char* argv[])
{
    char *device = (char *)malloc(IFNAMSIZ * sizeof(char));
    memset(device, '0', IFNAMSIZ);
    int opt = 0;

    while ((opt = getopt(argc, argv, "h:i")) != -1) {
        switch (opt)
        {
            case 'h':
                printf("Usage: %s [-h] [-i interface] \n", argv[0]);
                exit(0);
                break;
            case 'i':
                strcpy(device, optarg);
                break;
			      default:
				        printf("We will select the first device!\n");
        }
    }

    if (device[0] == '0') {
        if (get_first_device(device) != 0) {
            fprintf(stderr, "Error: couldn't find the firtst device to bind to~\n");
            return -1;
        }
    }

    init_env();

    if (handle_pkt_live(device, -1, 0) != TRUE) {
        fprintf(stderr, "Error: couldn't pcap and analysize the packet!\n");
        return -1;
    }

    return 0;
}
