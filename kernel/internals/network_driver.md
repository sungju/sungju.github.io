# Network Device Driver #

###Network layer ###

- In the below network layers, network device driver stays at the bottom just before the actual network card
- This can be different in behaving based on the type of network card such as Ethernet, Fiber, etc
- In each layer, it adds its own header
  - In the below, it adds 'EH' (Ethernet Header) and 'ET' (Ethernet Tail)

![Network Layer](https://sungju.github.io/kernel/internals/network_layer.png)

### Network device driver ###

- Writing network device driver uses the same functions for registering and unregsitering for any type of network drivers

```
/**
 *  register_netdev - register a network device
 *  @dev: device to register
 *
 *  Take a completed network device structure and add it to the kernel
 *  interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *  chain. 0 is returned on success. A negative errno code is returned
 *  on a failure to set up the device, or if the name is a duplicate.
 *
 *  This is a wrapper around register_netdevice that takes the rtnl semaphore
 *  and expands the device name if you passed a format string to
 *  alloc_netdev.
 */
int register_netdev(struct net_device *dev);

/**
 *  unregister_netdev - remove device from the kernel
 *  @dev: device
 *
 *  This function shuts down a device interface and removes it
 *  from the kernel tables.
 *
 *  This is just a wrapper for unregister_netdevice that takes
 *  the rtnl semaphore.  In general you want to use this and not
 *  unregister_netdevice.
 */
void unregister_netdev(struct net_device *dev);
```

- 'struct net_device' is used to specify all the network hardware related stuff, but it's really big one, so, helper functions are provided.
- Allocating general net_device can do done with the below functions.
  - sizeof_priv: specifying how much memory allocate in net_device.priv
  - name: device name. You can use a format string such as "eth%d"
  - setup(): Initialization function which will be called to fill net_device structure

```
struct net_device *alloc_netdev(sizeof_priv, name, setup);
void free_netdev(struct net_device *dev);
```

- Initializing net_device can be done with the one of the below functions based on the hardware type instead of calling above functions

```
struct net_device *alloc_etherdev(sizeof_priv); /* Ethernet device */
struct net_device *alloc_ltalkdev(int sizeof_priv); /* localtalk device */
struct net_device *alloc_fcdev(int sizeof_priv);  /* Fiber channel device */
struct net_device *alloc_fddidev(int sizeof_priv); /* FDDI device */
```

- Once it's initialzed, you can use net_device.priv with netdev_priv() function.

```
struct my_data *data = (struct my_data *)netdev_priv(my_dev);
```

- Once it's initialized, you may want to modify some fields
  - char name[IFNAMSIZ] : Interface name
  - unsigned long mem_start: Starting address of shared memory in the hardware
  - unsigned long mem_end: Ending address of shared memory in the hardware
  - unsigned long base_addr: Device's I/O address
  - unsigned char irq: IRQ number
  - unsigned char if_port: Specifying port number
  - unsinged long state: Device state
  - int features: Sharing hardware features with kernel
- There are many functions used during network driver operations which you can define in net_device.netdev_ops
  -   /* Management operations */ const struct net_device_ops *netdev_ops;
  - Example:

```
static const struct net_device_ops e100_netdev_ops = {
  .ndo_open   = e100_open,
  .ndo_stop   = e100_close,
  .ndo_start_xmit   = e100_send_packet,
  .ndo_tx_timeout   = e100_tx_timeout,
  .ndo_get_stats    = e100_get_stats,
  .ndo_set_rx_mode  = set_multicast_list,
  .ndo_do_ioctl   = e100_ioctl,
  .ndo_set_mac_address  = e100_set_mac_address,
...
};
```

- If it's ethernet device, there net_device.ethtool_ops in addition
  - Example

```
static const struct ethtool_ops e100_ethtool_ops = {
  .get_settings = e100_get_settings,
  .set_settings = e100_set_settings,
  .get_drvinfo  = e100_get_drvinfo,
  .nway_reset = e100_nway_reset,
  .get_link = ethtool_op_get_link,
}; 
```

- Initialization example : e1000

```
static int __init
etrax_ethernet_init(void)
{
  struct net_device *dev;
        struct net_local* np;
  int i, err;
...
  dev = alloc_etherdev(sizeof(struct net_local));
  if (!dev)
    return -ENOMEM;
 
  np = netdev_priv(dev);

  /* we do our own locking */
  dev->features |= NETIF_F_LLTX;

  dev->base_addr = (unsigned int)R_NETWORK_SA_0; /* just to have something to show */

  /* now setup our etrax specific stuff */

  dev->irq = NETWORK_DMA_RX_IRQ_NBR; /* we really use DMATX as well... */
  dev->dma = NETWORK_RX_DMA_NBR;

  /* fill in our handlers so the network layer can talk to us in the future */

  dev->ethtool_ops  = &e100_ethtool_ops;
  dev->netdev_ops   = &e100_netdev_ops;
...
  /* Register device */
  err = register_netdev(dev);  
  if (err) {
    free_netdev(dev);
    return err;
  } 
  
  /* set the default MAC address */
  
  e100_set_mac_address(dev, &default_mac);  
...
        /* Initialize mii interface */
  np->mii_if.phy_id_mask = 0x1f;
  np->mii_if.reg_num_mask = 0x1f;                                                 
  np->mii_if.dev = dev;
  np->mii_if.mdio_read = e100_get_mdio_reg;
  np->mii_if.mdio_write = e100_set_mdio_reg;
  
  /* Initialize group address registers to make sure that no */
  /* unwanted addresses are matched */
  *R_NETWORK_GA_0 = 0x00000000;
  *R_NETWORK_GA_1 = 0x00000000;
  
  /* Initialize next time the led can flash */
  led_next_time = jiffies;
  return 0;
} 
```

- Let's make a simple network device driver and see how it works.

```
/* mynet_drv.c */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/version.h>

static struct net_device *dev;
static struct net_device_stats *stats;
static void my_rx(struct sk_buff *skb, struct net_device *dev)
{
  /* just a loopback, already has the skb */
  printk("I'm receiving a packet\n");
  ++stats->rx_packets;
  netif_rx(skb);
}

static int my_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
  int i;
  printk("my_hard_start_xmit(%s)\n", dev->name);
  dev->trans_start = jiffies;
  printk("Sending packet :\n");
  /* print out 16 bytes per line */
  for (i = 0; i < skb->len; ++i) {
    if ((i & 0xf) == 0)
      printk("\n ");
    printk("%02x ", skb->data[i]);
  }
  printk("\n");
  ++stats->tx_packets;
  /* loopback it */
  /* In the real network device, it should send it through
   * Network hardware such as ethernet card.
   * Here we are just send it back to kernel by calling netif_rx().
   */
  my_rx(skb, dev);
  return 0;
}

static int my_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
  printk("my_do_ioctl(%s)\n", dev->name);
  /* Nothing to control here */
  /* You may want to check 'cmd' to do the actual operations */
  return -1;
}

static struct net_device_stats *my_get_stats(struct net_device *dev)
{
  printk("my_get_stats(%s)\n", dev->name);
  return stats;
}

/*
* This is where ifconfig comes down and tells us who we are, etc. * We can just ignore this.
*/
static int my_config(struct net_device *dev, struct ifmap *map)
{
  printk("my_config(%s)\n", dev->name);
  if (dev->flags & IFF_UP) {
    return -EBUSY;
  }
  return 0;
}

static int my_change_mtu(struct net_device *dev, int new_mtu)
{ 
  printk("my_change_mtu(%s)\n", dev->name);
  /* MTU changing is not allowed in this device */
  return -1;
}

static int my_open(struct net_device *dev)
{
  printk("my_open(%s)\n", dev->name);
  /* start up the transmission queue */
  /* Until this call, the device won't be available */
  netif_start_queue(dev);
  return 0;
}

static int my_close(struct net_device *dev)
{
  printk("my_close(%s)\n", dev->name);
  /* shutdown the transmission queue */
  netif_stop_queue(dev);
  return 0;
}

static const struct net_device_ops mynet_netdev_ops = {
  .ndo_open = my_open,
  .ndo_stop = my_close,
  .ndo_start_xmit = my_hard_start_xmit,
  .ndo_get_stats = my_get_stats,
  .ndo_do_ioctl = my_do_ioctl,
  .ndo_set_config = my_config,
  .ndo_change_mtu = my_change_mtu,
};

static void my_setup(struct net_device *dev)
{
  int j;
  printk("my_setup(%s)\n", dev->name);
  /* Fill in the MAC address with '00:01:02:03:04:05' */
  for (j = 0; j < ETH_ALEN; ++j) {
    dev->dev_addr[j] = (char)j;
  }
  /* Fill the data with ethernet specific values/operations */
  ether_setup(dev);
  dev->netdev_ops = &mynet_netdev_ops;
  /* We are not setting dev->ethtool_ops as it's not an actual 
   * ethernet device and ethool operations are not required */
  
  /* Not going to use ARP just like loopback device */
  dev->flags |= IFF_NOARP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
  stats = (struct net_device_stats *)
      kmalloc(sizeof(struct net_device_stats), GFP_KERNEL);
#else
  stats = &dev->stats;
#endif
} 

static int __init my_init(void)
{
  printk("Loading transmitting network module:....");
  dev = alloc_netdev(0, "mynet%d", my_setup);
  if (register_netdev(dev)) {
    printk(" Failed to register\n");
    free_netdev(dev);
    return -1;
  }
  printk("Succeeded!\n\n");
  return 0;
} 
  
static void __exit my_exit(void)
{ 
  printk("Unloading transmitting network module\n\n");
  unregister_netdev(dev);
  free_netdev(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
  kfree(stats);
#endif
}
  
module_init(my_init);
module_exit(my_exit);
```

- Usage: caution, ping won't be able to complete as receiving part is not working (no interrupt context)

```
$ insmod mynet_drv.ko
$ ifconfig mynet0 up 192.168.3.200
$ ping -bI mynet0 192.168.3

On another terminal, launch wireshark
$ wireshark
```


---
[Back to topic list](https://sungju.github.io/kernel/internals/index)
