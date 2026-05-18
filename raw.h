#ifndef RAW_H
#define RAW_H

#include "bridge.h"

// Dissect one raw packet and return a newly allocated JSON string.
// `link_type` is a libpcap LINKTYPE/DLT value and is translated to Wireshark's
// internal encapsulation before dissection.
char *dissect_raw_packet_json(const unsigned char *packet, int caplen, int len,
                              long sec, int nsec, int link_type, char *options);

#endif  // RAW_H
