#ifndef __MINERNET_H
#define __MINERNET_H

#ifdef __linux__

typedef int SOCKET;
#define closesocket close
#define INVALID_SOCKET	-1

#endif

int ConnectToPool(char *URL, char *Port);
int SetNonBlockingSocket(SOCKET sockfd);
void NetworkingShutdown(void);
int NetworkingInit(void);

#endif
