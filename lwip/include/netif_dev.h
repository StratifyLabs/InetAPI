/*
 * netif_dev.h
 *
 *  Created on: Apr 17, 2017
 *      Author: tgil
 */

#ifndef LWIP_NETIF_DEV_H_
#define LWIP_NETIF_DEV_H_

#include <sos/fs/sysfs.h>

typedef struct MCU_PACK {
	u8 hw_addr[6];
	u16 mtu /*! Default value should be 1500 */;
    sysfs_shared_config_t drive_config;
} netif_dev_config_t;



#endif /* LWIP_NETIF_DEV_H_ */
