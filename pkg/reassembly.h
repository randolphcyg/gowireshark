#ifndef FOLLOW_STREAM_H
#define FOLLOW_STREAM_H

#include <epan/dissectors/packet-tcp.h>
#include <epan/follow.h>
#include <epan/to_str.h>
#include <reassembly.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

void setup_tcp_follow_tap();

typedef void (*TcpTapDataCallback)(const char *json, int length, void *ctx);
void setTcpTapDataCallbackWithCtx(TcpTapDataCallback callback, void *ctx);
void GetTcpTapDataCallback(char *json, int length, void *ctx);

#endif  // FOLLOW_STREAM_H