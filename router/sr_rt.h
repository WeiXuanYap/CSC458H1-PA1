#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>

#include "sr_if.h"

/* ----------------------------------------------------------------------------
 * struct sr_rt
 *
 * Node in the routing table
 *
 * -------------------------------------------------------------------------- */

struct sr_rt {
  struct in_addr dest;
  struct in_addr gw;
  struct in_addr mask;
  char interface[sr_IFACE_NAMELEN];
  struct sr_rt *next;
};

int sr_load_rt(struct sr_instance *, const char *);
void sr_add_rt_entry(struct sr_instance *, struct in_addr, struct in_addr,
                     struct in_addr, char *);
void sr_print_routing_table(struct sr_instance *sr);
void sr_print_routing_entry(struct sr_rt *entry);

/* added method */
struct sr_rt *find_longest_match(struct sr_instance *, uint32_t);

#endif /* --  sr_RT_H -- */
