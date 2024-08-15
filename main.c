#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/lib.h"
#include "include/online.h"
#include "include/offline.h"

void data_callback(const char *data, int length, const char *metadata) {
    printf("Captured packet data: %.*s\n", length, data);
    printf("Packet metadata: %s\n", metadata);
}

/*
test command: device interface name: en7; bpfFilter: "tcp"; packet num: 3; promisc:true; timeout: 5s;
./main en7 "tcp" 3 1 5
*/
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <deviceName> [bpfFilter] [num] [promisc] [timeout s]\n", argv[0]);
        return -1;
    }

    // param
    char *deviceName = argv[1];
    char *bpfFilter = (argc > 2) ? argv[2] : "";
    int num = (argc > 3) ? atoi(argv[3]) : -1;
    int promisc = (argc > 4) ? atoi(argv[4]) : 0;
    int timeout = (argc > 5) ? atoi(argv[5]) : 1000;

    // check device
    if (strlen(deviceName) == 0) {
        fprintf(stderr, "Error: device name is empty\n");
        return -1;
    }

    init_env();

    // set callback
    setDataCallback(data_callback);

    // call handle_packet
    const char *errMsg = handle_packet(deviceName, bpfFilter, num, promisc, timeout);
    if (strlen(errMsg) != 0) {
        fprintf(stderr, "Failed to capture packet live: %s\n", errMsg);
        return -1;
    }

    printf("Packet capture completed successfully.\n");
    return 0;
}
