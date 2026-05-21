#ifndef TCP_FOLLOW_H
#define TCP_FOLLOW_H

#include <epan/dissectors/packet-tcp.h>
#include <epan/follow.h>
#include <epan/to_str.h>
#include <stdint.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

void setup_tcp_follow_tap();

typedef void (*TcpTapDataCallback)(const char *json, int length, uintptr_t ctx);
void setTcpTapDataCallbackWithCtx(TcpTapDataCallback callback, uintptr_t ctx);
void tcpFollowDataCallback(char *json, int length, uintptr_t ctx);

#endif  // TCP_FOLLOW_H
