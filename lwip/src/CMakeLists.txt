
set(LWIP_FOLDER ../lwip-2.1.2)

set(SOURCES
	netif_dev.c
	sys_arch.c
	lwip_api.c

	${LWIP_FOLDER}/src/api/api_lib.c
	${LWIP_FOLDER}/src/api/api_msg.c
	${LWIP_FOLDER}/src/api/err.c
	${LWIP_FOLDER}/src/api/netbuf.c
	${LWIP_FOLDER}/src/api/netdb.c
	${LWIP_FOLDER}/src/api/netifapi.c
	${LWIP_FOLDER}/src/api/sockets.c
	${LWIP_FOLDER}/src/api/tcpip.c
	${LWIP_FOLDER}/src/core/def.c
	${LWIP_FOLDER}/src/core/dns.c
	${LWIP_FOLDER}/src/core/inet_chksum.c
	${LWIP_FOLDER}/src/core/init.c
	${LWIP_FOLDER}/src/core/ip.c
	${LWIP_FOLDER}/src/core/mem.c
	${LWIP_FOLDER}/src/core/memp.c
	${LWIP_FOLDER}/src/core/netif.c
	${LWIP_FOLDER}/src/core/pbuf.c
	${LWIP_FOLDER}/src/core/raw.c
	${LWIP_FOLDER}/src/core/stats.c
	${LWIP_FOLDER}/src/core/sys.c
	${LWIP_FOLDER}/src/core/tcp_in.c
	${LWIP_FOLDER}/src/core/tcp_out.c
	${LWIP_FOLDER}/src/core/tcp.c
	${LWIP_FOLDER}/src/core/timeouts.c
	${LWIP_FOLDER}/src/core/udp.c

	${LWIP_FOLDER}/src/core/ipv4/autoip.c
	${LWIP_FOLDER}/src/core/ipv4/dhcp.c
	${LWIP_FOLDER}/src/core/ipv4/etharp.c
	${LWIP_FOLDER}/src/core/ipv4/icmp.c
	${LWIP_FOLDER}/src/core/ipv4/igmp.c
	${LWIP_FOLDER}/src/core/ipv4/ip4_addr.c
	${LWIP_FOLDER}/src/core/ipv4/ip4_frag.c
	${LWIP_FOLDER}/src/core/ipv4/ip4.c

	${LWIP_FOLDER}/src/core/ipv6/ethip6.c
	${LWIP_FOLDER}/src/core/ipv6/dhcp6.c
	${LWIP_FOLDER}/src/core/ipv6/icmp6.c
	${LWIP_FOLDER}/src/core/ipv6/ip6_addr.c
	${LWIP_FOLDER}/src/core/ipv6/ip6_frag.c
	${LWIP_FOLDER}/src/core/ipv6/ip6.c
	${LWIP_FOLDER}/src/core/ipv6/mld6.c
	${LWIP_FOLDER}/src/core/ipv6/nd6.c

	${LWIP_FOLDER}/src/netif/ppp/polarssl/arc4.c
	${LWIP_FOLDER}/src/netif/ppp/polarssl/des.c
	${LWIP_FOLDER}/src/netif/ppp/polarssl/md4.c
	${LWIP_FOLDER}/src/netif/ppp/polarssl/md5.c
	${LWIP_FOLDER}/src/netif/ppp/polarssl/sha1.c

	${LWIP_FOLDER}/src/netif/ethernet.c
	${LWIP_FOLDER}/src/netif/lowpan6.c
	${LWIP_FOLDER}/src/netif/slipif.c

	PARENT_SCOPE)
