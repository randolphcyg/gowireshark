#ifndef FOLLOW_STREAM_H
#define FOLLOW_STREAM_H

void setup_tcp_follow_tap();

typedef void (*TcpTapDataCallback)(const char *json, int length, void *ctx);
void setTcpTapDataCallbackWithCtx(TcpTapDataCallback callback, void *ctx);
void GetTcpTapDataCallback(char *json, int length, void *ctx);

#endif // FOLLOW_STREAM_H