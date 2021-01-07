/*
 * MeshVPN - A open source peer-to-peer VPN (forked from PeerVPN)
 *
 * Copyright (C) 2012-2016  Tobias Volk <mail@tobiasvolk.de>
 * Copyright (C) 2016       Hideman Developer <company@hideman.net>
 * Copyright (C) 2017       Benjamin Kübler <b.kuebler@kuebler-it.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef H_IO
#define H_IO

#if defined(__FreeBSD__)
#define IO_BSD
#elif defined(__APPLE__)
#define IO_BSD
#elif defined(WIN32)
#define IO_WINDOWS
#ifdef WINVER
#if WINVER < 0x0501
#undef WINVER
#endif
#endif
#ifndef WINVER
#define WINVER 0x0501
#endif
#else
#define IO_LINUX
#endif


#include "io.h"

#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>


#if defined(IO_LINUX) || defined(IO_BSD)
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#endif

#if defined(IO_LINUX)
#include <linux/if_tun.h>
#endif

#if defined(IO_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winioctl.h>
#endif


#define IO_TYPE_NULL 0
#define IO_TYPE_SOCKET_V6 1
#define IO_TYPE_SOCKET_V4 2
#define IO_TYPE_FILE 3

#define IO_ADDRTYPE_NULL "\x00\x00\x00\x00"
#define IO_ADDRTYPE_UDP6 "\x01\x06\x01\x00"
#define IO_ADDRTYPE_UDP4 "\x01\x04\x01\x00"



// The IO addr structure.
struct s_io_addr {
	unsigned char addr[24];
};


// The IO addrinfo structure.
struct s_io_addrinfo {
	struct s_io_addr item[16];
	int count;
};


// The IO handle structure.
struct s_io_handle {
	int enabled;
	int fd;
	struct sockaddr_storage source_sockaddr;
	struct s_io_addr source_addr;
	int group_id;
	int content_len;
	int type;
	int open;
#if defined(IO_WINDOWS)
	HANDLE fd_h;
	int open_h;
	OVERLAPPED ovlr;
	int ovlr_used;
	OVERLAPPED ovlw;
	int ovlw_used;
#endif
};


// The IO state structure.
struct s_io_state {
	unsigned char *mem;
	struct s_io_handle *handle;
	int bufsize;
	int max;
	int count;
	int timeout;
	int sockmark;
	int nat64clat;
	unsigned char nat64_prefix[12];
	int debug;
#if defined(IO_LINUX) || defined(IO_BSD)
	int epollfd;
#endif
};


// Returns length of string.
size_t ioStrlen(const char *str, const size_t max_len);

// Resolve name. Returns number of addresses.
int ioResolveName(struct s_io_addrinfo *iai, const char *hostname, const char *port);

// Reset handle ID values and buffers.
void ioResetID(struct s_io_state *iostate, const int id);

// Allocates a handle ID. Returns ID if succesful, or -1 on error.
int ioAllocID(struct s_io_state *iostate);

// Deallocates a handle ID.
void ioDeallocID(struct s_io_state *iostate, const int id);

// Closes a handle ID.
void ioClose(struct s_io_state *iostate, const int id);

// Opens a socket. Returns handle ID if successful, or -1 on error.
int ioOpenSocket(struct s_io_state *iostate, const int iotype, const char *bindaddress, const char *bindport, const int domain, const int type, const int protocol);

// Opens an IPv6 UDP socket. Returns handle ID if successful, or -1 on error.
int ioOpenSocketV6(struct s_io_state *iostate, const char *bindaddress, const char *bindport);

// Opens an IPv4 UDP socket. Returns handle ID if successful, or -1 on error.
int ioOpenSocketV4(struct s_io_state *iostate, const char *bindaddress, const char *bindport);

// Helper functions for TAP devices on Windows.
#if defined(IO_WINDOWS)

char *ioOpenTAPWINSearch(char *value, char *key, int type)

HANDLE ioOpenTAPWINDev(char *guid, char *dev);

HANDLE ioOpenTAPWINHandle(char *tapname, const char *reqname, const int reqname_len);
#endif


// Opens a TAP device. Returns handle ID if succesful, or -1 on error.
int ioOpenTAP(struct s_io_state *iostate, char *tapname, const char *reqname);

// Opens STDIN. Returns handle ID if succesful, or -1 on error.
int ioOpenSTDIN(struct s_io_state *iostate);

// Receives an UDP packet. Returns length of received message, or 0 if nothing is received.
int ioHelperRecvFrom(struct s_io_handle *handle, unsigned char *recv_buf, const int recv_buf_size, struct sockaddr *source_sockaddr, socklen_t *source_sockaddr_len);

#if defined(IO_WINDOWS)
// Finish receiving an UDP packet. Returns amount of bytes read, or 0 if nothing is read.
int ioHelperFinishRecvFrom(struct s_io_handle *handle);
#endif


// Sends an UDP packet. Returns length of sent message.
int ioHelperSendTo(struct s_io_handle *handle, const unsigned char *send_buf, const int send_buf_size, const struct sockaddr *destination_sockaddr, const socklen_t destination_sockaddr_len);

// Reads from file. Returns amount of bytes read, or 0 if nothing is read.
int ioHelperReadFile(struct s_io_handle *handle, unsigned char *read_buf, const int read_buf_size);

#if defined(IO_WINDOWS)
// Finish reading from file. Returns amount of bytes read, or 0 if nothing is read.
int ioHelperFinishReadFile(struct s_io_handle *handle);
#endif

// Writes to file. Returns amount of bytes written.
int ioHelperWriteFile(struct s_io_handle *handle, const unsigned char *write_buf, const int write_buf_size);

// Prepares read operation on specified handle ID.
void ioPreRead(struct s_io_state *iostate, const int id);

// Reads data on specified handle ID. Returns amount of bytes read, or 0 if nothing is read.
int ioRead(struct s_io_state *iostate, const int id);

// Waits for data on any handle and read it. Returns the amount of handles where data have been read.
int ioReadAll(struct s_io_state *iostate);

// Writes data on specified handle ID. Returns amount of bytes written.
int ioWrite(struct s_io_state *iostate, const int id, const unsigned char *write_buf, const int write_buf_size, const struct s_io_addr *destination_addr);

// Writes data on one handle ID of the specified group. Returns amount of bytes written.
int ioWriteGroup(struct s_io_state *iostate, const int group, const unsigned char *write_buf, const int write_buf_size, const struct s_io_addr *destination_addr);

// Returns the first handle of the specified group that has data, or -1 if there is none.
int ioGetGroup(struct s_io_state *iostate, const int group);

// Returns a pointer to the data buffer of the specified handle ID.
unsigned char * ioGetData(struct s_io_state *iostate, const int id);

// Returns the data buffer content length of the specified handle ID, or zero if there are no data.
int ioGetDataLen(struct s_io_state *iostate, const int id);

// Returns a pointer to the current source address of the specified handle ID.
struct s_io_addr * ioGetAddr(struct s_io_state *iostate, const int id);

// Clear data of the specified handle ID.
void ioGetClear(struct s_io_state *iostate, const int id);

// Set group ID of handle ID
void ioSetGroup(struct s_io_state *iostate, const int id, const int group);

// Set sockmark value for new sockets.
void ioSetSockmark(struct s_io_state *iostate, const int io_sockmark);

// Enable/Disable NAT64 CLAT support.
void ioSetNat64Clat(struct s_io_state *iostate, const int enable);

// Set IO read timeout (in seconds).
void ioSetTimeout(struct s_io_state *iostate, const int io_timeout);

// Closes all handles and resets defaults.
void ioReset(struct s_io_state *iostate);

// Create IO state structure. Returns 1 on success.
int ioCreate(struct s_io_state *iostate, const int io_bufsize, const int io_max);

// Destroy IO state structure.
void ioDestroy(struct s_io_state *iostate);

#endif
