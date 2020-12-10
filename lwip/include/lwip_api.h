#ifndef LWIP_API_H_
#define LWIP_API_H_

#include <sos/fs/devfs.h>
#include <sys/socket.h>

#include "lwip/netdb.h"
#include "lwip/netif.h"
#include "lwip/sockets.h"

typedef struct {
  sysfs_shared_config_t device_config; // identifies the device to use
  struct netif *lwip_netif;            // pointer to the RAM for lwip netif
  u8 *packet_buffer;                   // pointer to packet buffer RAM
  u16 packet_buffer_size;
  const char *host_name;
  void (*netif_status_callback)(struct netif *netif);
} lwip_api_netif_config_t;

typedef struct {
  const lwip_api_netif_config_t *netif_config;
  u16 netif_config_count;
} lwip_api_config_t;

typedef struct {
  err_t (*init_function)(struct netif *);
  err_t (*input_function)(struct pbuf *, struct netif *);
} lwip_api_netif_t;

typedef struct {
  const lwip_api_config_t *config;
} lwip_api_state_t;

int lwip_api_startup(const void *socket_api);
int lwip_api_deinitialize();
in_addr_t lwip_inet_addr(const char *cp);
char *lwip_inet_ntoa(struct in_addr addr);
const char *lwip_inet_ntop(int af, const void *src, char *dst, socklen_t size);
int lwip_inet_pton(int af, const char *src, void *dst);

#define LWIP_DECLARE_CONFIG_STATE(                                             \
    name_value, network_interface_count_value, device_filesystem_value,        \
    device_name_value, host_name_value, mtu_value, max_packet_size_value,      \
    hw_addr_0_value, hw_addr_1_value, hw_addr_2_value, hw_addr_3_value,        \
    hw_addr_4_value, hw_addr_5_value)                                          \
  lwip_api_netif_state_t name_value##_state;                                   \
  struct netif                                                                 \
      name_value##_network_interface_list[network_interface_count_value];      \
  u8 name_value##_packet_buffer[max_packet_size_value];                        \
  lwip_api_config_t name_value##_config = {                                    \
      .device_config.devfs = device_filesystem_value,                          \
      .device_config.name = device_name_value,                                 \
      .device_config.state = name_value##_state,                               \
      .hw_addr[0] = hw_addr_0_value,                                           \
      .hw_addr[1] = hw_addr_1_value,                                           \
      .hw_addr[2] = hw_addr_2_value,                                           \
      .hw_addr[3] = hw_addr_3_value,                                           \
      .hw_addr[4] = hw_addr_4_value,                                           \
      .hw_addr[5] = hw_addr_5_value,                                           \
      .mtu = mtu_value,                                                        \
      .max_packet_size = max_packet_size_value,                                \
      .netif_device_attr = netif_device_attr_value,                            \
      .host_name = host_name_value,                                            \
      .network_interface_list = name_value##_network_interface_list,           \
      .network_interface_count = network_interface_count_value}

#define LWIP_DECLARE_SOCKET_API(api_name, api_config, api_state)               \
  const sos_socket_api_t api_name##_api = {                                    \
      .startup = lwip_api_startup,                                             \
      .accept = lwip_accept,                                                   \
      .bind = lwip_bind,                                                       \
      .shutdown = lwip_shutdown,                                               \
      .getpeername = lwip_getpeername,                                         \
      .getsockname = lwip_getsockname,                                         \
      .getsockopt = lwip_getsockopt,                                           \
      .setsockopt = lwip_setsockopt,                                           \
      .close = lwip_close,                                                     \
      .connect = lwip_connect,                                                 \
      .read = lwip_read,                                                       \
      .listen = lwip_listen,                                                   \
      .recv = lwip_recv,                                                       \
      .recvfrom = lwip_recvfrom,                                               \
      .send = lwip_send,                                                       \
      .sendmsg = lwip_sendmsg,                                                 \
      .sendto = lwip_sendto,                                                   \
      .socket = lwip_socket,                                                   \
      .write = lwip_write,                                                     \
      .writev = lwip_writev,                                                   \
      .select = lwip_select,                                                   \
      .ioctl = lwip_ioctl,                                                     \
      .fcntl = lwip_fcntl,                                                     \
      .fsync = 0,                                                              \
      .gethostbyname = lwip_gethostbyname,                                     \
      .gethostbyname_r = lwip_gethostbyname_r,                                 \
      .freeaddrinfo = lwip_freeaddrinfo,                                       \
      .getaddrinfo = lwip_getaddrinfo,                                         \
      .inet_addr = lwip_inet_addr,                                             \
      .inet_ntoa = lwip_inet_ntoa,                                             \
      .inet_ntop = lwip_inet_ntop,                                             \
      .inet_pton = lwip_inet_pton,                                             \
      .config = api_config,                                                    \
      .state = api_state}

#endif /* LWIP_HDR_LWIPOPTS_H__ */
