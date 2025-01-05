#ifndef FOLLOW_STREAM_H
#define FOLLOW_STREAM_H

void setup_tcp_follow_tap();

void print_tcp_streams();

void close_socket(int sock);

typedef void (*TcpTapDataCallback)(const char *, int);
void GetTcpTapDataCallback(char *data, int length);
void setTcpTapDataCallback(TcpTapDataCallback callback);

#endif // FOLLOW_STREAM_H