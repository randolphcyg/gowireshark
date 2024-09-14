#include "include/lib.h"
#include "include/offline.h"
#include "include/online.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ./main -l en7 "tcp" 3 1 5
// device interface name: en7; bpfFilter: "tcp"; packet num: 3; promisc:true;
// timeout: 5s;
void test_live_packet_capture(char *d, char *b, int n, int p, int t);
// ./main -sf "./pcaps/mysql.pcapng" 0 20 1 0
void test_packet_file_read_specific_frame(char *filepath, int c, int n, int des,
                                          int deb);
// ./main -af "./pcaps/mysql.pcapng" 1 0
void test_packet_file_read_all_frame(char *filepath, int des, int deb);

void data_callback(const char *data, int length, const char *metadata) {
  printf("Captured packet data: %.*s\n", length, data);
  printf("Packet metadata: %s\n", metadata);
}

/*
make first
*/
int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "For live packet capture: %s -l <d> [b] [n] [p] [t]\n",
            argv[0]);
    fprintf(stderr,
            "For reading packet file: %s -f <filepath> [c] [n] [des] [deb]\n",
            argv[0]);
    return -1;
  }

  // Check if user wants to perform live packet capture (-l) or file reading
  // (-f)
  if (strcmp(argv[1], "-l") == 0) {
    if (argc < 3) {
      fprintf(stderr,
              "Usage for live packet capture: %s -l <d> [b] [n] [p] [t]\n",
              argv[0]);
      return -1;
    }

    // Set parameters for live packet capture
    char *d = argv[2];                         // Device name
    char *b = (argc > 3) ? argv[3] : "";       // BPF filter
    int n = (argc > 4) ? atoi(argv[4]) : -1;   // Number of packets to capture
    int p = (argc > 5) ? atoi(argv[5]) : 0;    // Promiscuous mode flag
    int t = (argc > 6) ? atoi(argv[6]) : 1000; // Timeout in seconds

    // Call live packet capture test function
    test_live_packet_capture(d, b, n, p, t);

  } else if (strcmp(argv[1], "-sf") == 0) {
    if (argc < 3) {
      fprintf(stderr,
              "Usage for reading packet file: %s -f <filepath> [c] [n] [des] "
              "[deb]\n",
              argv[0]);
      return -1;
    }

    // Set the file path and optional parameters for reading the packet file
    char *filepath = argv[2];
    int c = (argc > 3) ? atoi(argv[3]) : 0;   // Counter start value
    int n = (argc > 4) ? atoi(argv[4]) : 10;  // Number of packets to process
    int des = (argc > 5) ? atoi(argv[5]) : 1; // Descriptive flag
    int deb = (argc > 6) ? atoi(argv[6]) : 0; // Debug flag

    // Call packet file reading test function
    test_packet_file_read_specific_frame(filepath, c, n, des, deb);

  } else if (strcmp(argv[1], "-af") == 0) {
    if (argc < 3) {
      fprintf(stderr,
              "Usage for reading packet file: %s -f <filepath> [des] [deb]\n",
              argv[0]);
      return -1;
    }

    // Set the file path and optional parameters for reading the packet file
    char *filepath = argv[2];
    int des = (argc > 3) ? atoi(argv[3]) : 1; // Descriptive flag
    int deb = (argc > 4) ? atoi(argv[4]) : 0; // Debug flag

    test_packet_file_read_all_frame(filepath, des, deb);

  } else {
    fprintf(stderr,
            "Invalid option. Use -l for live capture or -af -sf for file read.\n");
    return -1;
  }

  return 0;
}

// Function for testing live packet capture
void test_live_packet_capture(char *d, char *b, int n, int p, int t) {
  // Initialize the environment
  init_env();

  // Set callback function
  setDataCallback(data_callback);

  // Handle live packet capture
  const char *errMsg = handle_packet(d, b, n, p, t);
  if (strlen(errMsg) != 0) {
    fprintf(stderr, "Failed to capture packet live: %s\n", errMsg);
  } else {
    printf("Packet capture completed successfully.\n");
  }
}

void test_packet_file_read_all_frame(char *filepath, int des, int deb) {
  // Initialize the environment
  init_env();

  // Initialize the packet capture file
  int errNo = init_cf(filepath);
  if (errNo != 0) {
    fprintf(stderr, "Error: %s\n", strerror(errNo));
    return;
  }

  int counter = 0;
  while (1) {
    counter++;
    // Get protocol analysis result in JSON format
    char *srcFrame = proto_tree_in_json(counter, des, deb);
    if (srcFrame != NULL) {
      if (strlen(srcFrame) == 0) {
        break;
      }
      printf("%s\n", srcFrame);
    }
  }
}

// Function for testing packet file reading
void test_packet_file_read_specific_frame(char *filepath, int c, int n, int des,
                                          int deb) {
  // Initialize the environment
  init_env();

  // Initialize the packet capture file
  int errNo = init_cf(filepath);
  if (errNo != 0) {
    fprintf(stderr, "Error: %s\n", strerror(errNo));
    return;
  }

  int counter = c;
  while (counter < n) {
    counter++;
    // Get protocol analysis result in JSON format
    char *srcFrame = proto_tree_in_json(counter, des, deb);
    if (srcFrame != NULL) {
      if (strlen(srcFrame) == 0) {
        break;
      }
      printf("%s\n", srcFrame);
    }
  }
}
