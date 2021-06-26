#ifndef LWIP_HDR_LWIPOPTS_H__
#define LWIP_HDR_LWIPOPTS_H__

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* Prevent having to link sys_arch.c (we don't test the API layers in unit
 * tests) */
#define NO_SYS 0
#define LWIP_NETCONN 1
#define LWIP_DNS 1
#define LWIP_SOCKET 1
#define LWIP_RAW 0
#define LWIP_COMPAT_MUTEX_ALLOWED 1
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1
#define MEMP_OVERFLOW_CHECK 0
#define MEM_ALIGNMENT 4
#define ETH_PAD_SIZE 0
#define LWIP_SOCKET_OFFSET OPEN_MAX
#define TCPIP_THREAD_PRIO 10

#define LWIP_POSIX_SOCKETS_IO_NAMES 0
#define LWIP_COMPAT_SOCKETS 0
#define LWIP_NETIF_HOSTNAME 1

#define LWIP_IPV6 1
#define IPV6_FRAG_COPYHEADER 1
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS 0
#define LWIP_DHCP_CHECK_LINK_UP 1
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#define LWIP_SO_RCVTIMEO 1
#define LWIP_SO_SNDTIMEO 1
#define LWIP_SO_RCVBUF 1
#define LWIP_MPU_COMPATIBLE 1

#define ARP_TABLE_SIZE 64

//#define LWIP_ERRNO_INCLUDE <errno.h>

// this lets LWIP tell the system when the IP address changes
#define LWIP_NETIF_STATUS_CALLBACK 1

/* Enable DHCP to test it */
#define LWIP_DHCP 1

#if defined ___debug
#define LWIP_DEBUG 1

//#define ETHARP_DEBUG 0x80
#define TCPIP_DEBUG 0x80
//#define DNS_DEBUG 0x80
#define TCP_DEBUG 0x80
#define TCP_OUTPUT_DEBUG 0x80
#define TCP_INPUT_DEBUG 0x80
#define TRACE_DEBUG 0x80
#define SOCKETS_DEBUG 0x80
#define UDP_DEBUG 0x80
#define DHCP_DEBUG 0x80
#define AUTOIP_DEBUG 0x80
#define API_LIB_DEBUG 0x80
#define API_MSG_DEBUG 0x80
#define NETIF_DEBUG 0x80
#define IP_DEBUG 0x80
#define TCP_CWND_DEBUG 0x80
//#define PBUF_DEBUG 0x80
#define LWIP_DBG_MIN_LEVEL 0

#endif

/* Checksum settings */
// STM32 ethernet has checksum generation built-in
#if _LWIP_NO_CRC
#define CHECKSUM_GEN 0
#define LWIP_CHECKSUM_ON_COPY 0
#else
#define CHECKSUM_GEN 0
#define LWIP_CHECKSUM_ON_COPY 0
#endif

#define CHECKSUM_GEN_IP CHECKSUM_GEN
#define CHECKSUM_GEN_UDP CHECKSUM_GEN
#define CHECKSUM_GEN_TCP CHECKSUM_GEN
#define CHECKSUM_GEN_ICMP CHECKSUM_GEN
#define CHECKSUM_GEN_ICMP6 CHECKSUM_GEN

#define CHECKSUM_CHECK_IP CHECKSUM_GEN
#define CHECKSUM_CHECK_UDP CHECKSUM_GEN
#define CHECKSUM_CHECK_TCP CHECKSUM_GEN
#define CHECKSUM_CHECK_ICMP CHECKSUM_GEN
#define CHECKSUM_CHECK_ICMP6 CHECKSUM_GEN

#define MEM_SIZE 32768

#define MEMP_NUM_TCP_PCB 4
#define MEMP_NUM_TCP_PCB_LISTEN 4
#define TCP_LISTEN_BACKLOG 4
#define TCP_MSS (1460)

#define LWIP_TCP_SACK_OUT 1
#define LWIP_TCP_MAX_SACK_NUM 4

#define TCP_WND (4 * TCP_MSS)
#define TCP_SND_BUF TCP_WND // same as TCP_WND for max throughput
#define TCP_OVERSIZE TCP_MSS

#define TCPIP_THREAD_STACKSIZE 2048

#define sys_msleep sys_arch_msleep

/* Minimal changes to opt.h required for etharp unit tests: */
#define ETHARP_SUPPORT_STATIC_ENTRIES 1

#endif // LWIP_HDR_LWIPOPTS_H__
