
#include <errno.h>
#include <sos/debug.h>
#include <sos/dev/netif.h>
#include <sos/fs/sysfs.h>
#include <sos/sos.h>
#include <unistd.h>

#include <cortexm/cortexm.h>
#include <cortexm/task.h>

#include "lwip/dhcp.h"
#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "lwip_api.h"

#include "lwip/def.h"
#include "lwip/etharp.h"
#include "lwip/ethip6.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/snmp.h"
#include "lwip/stats.h"
#include "lwip/tcpip.h"
#include "netif/ppp/pppoe.h"

static void lwip_input_thread(void *arg) MCU_NO_RETURN; // monitor each input
static int lwip_api_netif_is_link_up(struct netif *netif);
static err_t lwip_api_netif_init(struct netif *netif);
static err_t lwip_api_netif_input(struct netif *netif);
static err_t lwip_api_netif_output(struct netif *netif, struct pbuf *p);
static int lwip_api_add_netif(const lwip_api_netif_config_t *netif_config);

err_t lwip_api_netif_init(struct netif *netif) {
  /* set MAC hardware address length */
  const lwip_api_netif_config_t *config = netif->state;

  sos_debug_log_info(SOS_DEBUG_SOCKET, "Host name is %s", config->host_name);
  netif->hostname = config->host_name;

  /* maximum transfer unit */
  netif->output = etharp_output;
#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif

  netif->linkoutput = lwip_api_netif_output;
  netif->name[0] = config->device_config.name[0];
  netif->name[1] = config->device_config.name[1];

  netif_attr_t attr;
  int result;

  if ((result = sysfs_shared_open(&config->device_config)) < 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET,
                        "Failed to open network interface %s (%d, %d)",
                        config->device_config.name, result, errno);
    return ERR_IF;
  }

  attr.o_flags = NETIF_FLAG_INIT;
  result = sysfs_shared_ioctl(&config->device_config, I_NETIF_SETATTR, &attr);
  if (result < 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET,
                        "Failed to init network interface (%d, %d)", result,
                        errno);
    return ERR_IF;
  }

  netif_info_t netif_device_info;
  if ((result = sysfs_shared_ioctl(&config->device_config, I_NETIF_GETINFO,
                                   &netif_device_info)) < 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET,
                        "Failed to get info from netif device (%d,%d)", result,
                        errno);
    return ERR_IF;
  }

  memcpy(netif->hwaddr, netif_device_info.mac_address, NETIF_MAX_HWADDR_LEN);
  netif->hwaddr_len = ETHARP_HWADDR_LEN;
  netif->mtu = netif_device_info.mtu;
  netif->flags =
      (netif_device_info.o_flags & NETIF_FLAG_IS_BROADCAST
           ? NETIF_FLAG_BROADCAST
           : 0) |
      (netif_device_info.o_flags & NETIF_FLAG_IS_ETHERNET ? NETIF_FLAG_ETHERNET
                                                          : 0) |
      (netif_device_info.o_flags & NETIF_FLAG_IS_ETHERNET_ARP
           ? NETIF_FLAG_ETHARP
           : 0) |
      (netif_device_info.o_flags & NETIF_FLAG_IS_IGMP ? NETIF_FLAG_IGMP : 0) |
      (netif_device_info.o_flags & NETIF_FLAG_IS_MLD6 ? NETIF_FLAG_MLD6 : 0);

  MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 10000);

  sos_debug_log_info(SOS_DEBUG_SOCKET, "NETIF Init complete");
  return ERR_OK;
}

int lwip_api_netif_is_link_up(struct netif *netif) {
  const lwip_api_netif_config_t *config = netif->state;
  netif_attr_t attr = {0};
  attr.o_flags = NETIF_FLAG_IS_LINK_UP;
  return sysfs_shared_ioctl(&config->device_config, I_NETIF_SETATTR, &attr);
}

int lwip_api_netif_set_link_up(struct netif *netif) {
  const lwip_api_netif_config_t *config = netif->state;
  netif_attr_t attr = {0};
  attr.o_flags = NETIF_FLAG_SET_LINK_UP;
  return sysfs_shared_ioctl(&config->device_config, I_NETIF_SETATTR, &attr);
}

int lwip_api_netif_set_link_down(struct netif *netif) {
  const lwip_api_netif_config_t *config = netif->state;
  netif_attr_t attr = {0};
  attr.o_flags = NETIF_FLAG_SET_LINK_DOWN;
  return sysfs_shared_ioctl(&config->device_config, I_NETIF_SETATTR, &attr);
}

err_t lwip_api_netif_input(struct netif *netif) {
  const lwip_api_netif_config_t *config = netif->state;
  struct pbuf *q;
  struct pbuf *p;
  int len;

  u16 offset = 0;

  /* Obtain the size of the packet and put it into the "len"
          variable. */
  // len = ioctl(netif_dev->fd, I_NETIF_LEN);
  len = sysfs_shared_read(&config->device_config, 0, config->packet_buffer,
                          config->packet_buffer_size);
  if (len <= 0) {
    return ERR_IF;
  }

  sos_debug_log_info(SOS_DEBUG_SOCKET, "Got %d bytes", len);

#if ETH_PAD_SIZE
  len += ETH_PAD_SIZE; /* allow room for Ethernet padding */
#endif

  /* We allocate a pbuf chain of pbufs from the pool. */
  p = pbuf_alloc_reference(config->packet_buffer, (u16_t)len, PBUF_REF);

  if (p != NULL) {

#if ETH_PAD_SIZE
    pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif

    /* We iterate over the pbuf chain until we have read the entire
     * packet into the pbuf. */
    for (q = p; q != NULL; q = q->next) {
      /* Read enough bytes to fill this pbuf in the chain. The
       * available data in the pbuf is given by the q->len
       * variable.
       * This does not necessarily have to be a memcpy, you can also preallocate
       * pbufs for a DMA-enabled MAC and after receiving truncate it to the
       * actually received size. In this case, ensure the tot_len member of the
       * pbuf is the sum of the chained pbuf len members.
       */

      // scatter the packet into the pbuf
      memcpy(q->payload, config->packet_buffer + offset, q->len);
      offset += q->len;
    }
    // acknowledge that packet has been read();

    MIB2_STATS_NETIF_ADD(netif, ifinoctets, p->tot_len);
    if (((u8_t *)p->payload)[0] & 1) {
      /* broadcast or multicast packet*/
      MIB2_STATS_NETIF_INC(netif, ifinnucastpkts);
    } else {
      /* unicast packet*/
      MIB2_STATS_NETIF_INC(netif, ifinucastpkts);
    }

#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

    /* if no packet could be read, silently ignore this */
    if (len > 0) {

      /* pass all packets to ethernet_input, which decides what packets it
       * supports */
      if (netif->input(p, netif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG, ("netif_dev_input: IP input error\n"));
        pbuf_free(p);
        p = NULL;
      }
    }

    LINK_STATS_INC(link.recv);
  } else {
    // drop packet();
    LINK_STATS_INC(link.memerr);
    LINK_STATS_INC(link.drop);
    MIB2_STATS_NETIF_INC(netif, ifindiscards);
  }

  return ERR_OK;
}

err_t lwip_api_netif_output(struct netif *netif, struct pbuf *p) {
  const lwip_api_netif_config_t *config = netif->state;
  struct pbuf *q;
  int result;

  // initiate transfer();

  sos_debug_log_info(SOS_DEBUG_SOCKET, "write interface (%d, %p)", p->tot_len,
                     p);

#if ETH_PAD_SIZE
  pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif

  for (q = p; q != NULL; q = q->next) {
    /* Send the data from the pbuf to the interface, one pbuf at a
     time. The size of the data in each pbuf is kept in the ->len
     variable. */
    // send data from(q->payload, q->len);
#if 0
    for (int i = 0; i < q->len; i++) {
      if (i % 16 == 0) {
        sos_debug_printf("\n%p 0x%04X:", i, q->payload);
      }
      sos_debug_printf("%02X ", ((u8 *)q->payload)[i]);
    }
    sos_debug_printf("\n");
#endif

    if ((result = sysfs_shared_write(&config->device_config, 0, q->payload,
                                     q->len)) != q->len) {
      sos_debug_log_error(SOS_DEBUG_SOCKET, "Failed to write (%d,%d)\n", result,
                          errno);
      return ERR_IF;
    }
    // sos_debug_log_info(SOS_DEBUG_SOCKET, "sent:%d", result);
  }

  MIB2_STATS_NETIF_ADD(netif, ifoutoctets, p->tot_len);
  if (((u8_t *)p->payload)[0] & 1) {
    /* broadcast or multicast packet*/
    MIB2_STATS_NETIF_INC(netif, ifoutnucastpkts);
  } else {
    /* unicast packet */
    MIB2_STATS_NETIF_INC(netif, ifoutucastpkts);
  }

#if ETH_PAD_SIZE
  pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

  return ERR_OK;
}

void tcpip_init_done(void *args) {
  MCU_UNUSED_ARGUMENT(args);
  usleep(800 * 1000);
  sos_debug_log_info(SOS_DEBUG_SOCKET, "TCPIP INIT DONE %d", pthread_self());
  if (setuid(SYSFS_ROOT) < 0) {
    sos_debug_log_info(SOS_DEBUG_SOCKET,
                       "failed to set root user -- may crash later");
  }
}

int lwip_api_startup(const void *socket_api) {

  const lwip_api_config_t *config =
      ((const sos_socket_api_t *)socket_api)->config;
  u32 i;

  if (config->netif_config_count == 0) {
    sos_debug_log_error(SOS_DEBUG_SOCKET, "No network interfaces");
    return -1;
  }

  sos_debug_log_info(SOS_DEBUG_SOCKET, "TCPIP Init");
  tcpip_init(tcpip_init_done, 0);

  usleep(100 * 1000);

  // state is passed around as part of netif, it needs to link back to config
  sos_debug_printf("socket api: %p config:%p\n", socket_api, config);

  for (i = 0; i < config->netif_config_count; i++) {
    sos_debug_log_info(SOS_DEBUG_SOCKET, "Add NETIF %d of %d", i + 1,
                       config->netif_config_count);
    if (lwip_api_add_netif(config->netif_config + i) < 0) {
      sos_debug_log_error(SOS_DEBUG_SOCKET, "Failed to add interface %d of %d",
                          i + 1, config->netif_config_count);
      return -1;
    }
  }

  sos_debug_log_info(SOS_DEBUG_SOCKET, "Set default network interface %p",
                     config->netif_config[0].lwip_netif);

  netif_set_default(config->netif_config[0].lwip_netif);

  // allow NETIF to come up
  usleep(250 * 1000);

  return 0;
}

int lwip_api_deinitialize() {
  // stop the input thread

  return 0;
}

int lwip_api_add_netif(const lwip_api_netif_config_t *netif_config) {

  if (getpid() != 0) {
    // this can only be called from the kernel task
    sos_debug_log_error(SOS_DEBUG_SOCKET,
                        "Cannot add netif except from kernel");
    return -1;
  }

  struct netif *netif = netif_config->lwip_netif;

  netif_add(netif,
#if LWIP_IPV4
            (const ip4_addr_t *)IP4_ADDR_ANY, // ip addr
            (const ip4_addr_t *)IP4_ADDR_ANY, // ip netmask
            (const ip4_addr_t *)IP4_ADDR_ANY, // gw
#endif
            (void *)netif_config, lwip_api_netif_init, tcpip_input);

  netif_set_status_callback(netif, netif_config->netif_status_callback);

  // create a thread to monitor the new interface - for up/down, etc
  sys_thread_new("netif", lwip_input_thread, netif, 1024 * 2,
                 TCPIP_THREAD_PRIO);

  sos_debug_log_info(SOS_DEBUG_SOCKET, "Added netif %s", netif->hostname);
  return 0;
}

void lwip_input_thread(void *arg) {
  // this thread monitors each network interface for incoming traffic
  struct netif *netif = (struct netif *)arg;

  sos_debug_log_info(SOS_DEBUG_SOCKET, "Start thread %s", netif->hostname);

  while (1) {

    sos_debug_log_info(SOS_DEBUG_SOCKET, "netif %p: is waiting to come up",
                       netif);
    while (lwip_api_netif_is_link_up(netif) <= 0) {
      usleep(100 * 1000);
    }

    sos_debug_log_info(SOS_DEBUG_SOCKET, "netif %p: is up", netif);
    netif_set_link_up(netif);
    netif_set_up(netif);
    usleep(500*1000);
    usleep(500*1000);
    usleep(500*1000);
    usleep(500*1000);
    usleep(500*1000);
    usleep(500*1000);
    usleep(500*1000);
    usleep(500*1000);
    usleep(500*1000);
    sos_debug_printf("host name is at %p\n", netif->hostname);
    dhcp_start(netif);

    while (lwip_api_netif_is_link_up(netif) > 0) {
      const int input_result = lwip_api_netif_input(netif);

      // ERR_OK means data arrived -- keep reading the if until no data arrives
      // -- then sleep
      if (input_result != ERR_OK) {
        usleep(10 * 1000); // wait a bit before checking for a frame again
      }
    }

    sos_debug_log_info(SOS_DEBUG_SOCKET, "netif %p: is down", netif);
    netif_set_link_down(netif);
    netif_set_down(netif);
    dhcp_stop(netif);
  }
}

in_addr_t lwip_inet_addr(const char *cp) { return ipaddr_addr(cp); }
char *lwip_inet_ntoa(struct in_addr addr) {
  return ip4addr_ntoa((const ip4_addr_t *)&(addr));
}
#if 0
const char * lwip_inet_ntop(int af, const void * src, char * dst, socklen_t size){
	return (((af) == AF_INET6) ? ip6addr_ntoa_r((const ip6_addr_t*)(src),(dst),(size))
														 : (((af) == AF_INET) ? ip4addr_ntoa_r((const ip4_addr_t*)(src),(dst),(size)) : NULL));
}
int lwip_inet_pton(int af, const char * src, void * dst){
	return (((af) == AF_INET6) ? ip6addr_aton((src),(ip6_addr_t*)(dst)) : 0);
}
#endif
