#include <assert.h>
#include <stdio.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */

} /* -- sr_init -- */


void send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, 
                  struct sr_if* interface, uint32_t dest_ip) {
  return;
}

void send_icmp(struct sr_instance *sr, uint8_t *p_frame, unsigned int len,
               uint8_t type, uint8_t code) {
  // p_frame is packet's raw frame.
  // point structs to ethernet, ip headers accordingly.
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)p_frame;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(p_frame + sizeof(sr_ethernet_hdr_t));

  // need to find destination interface
  // find longest matching prefix of src ip since icmp goes back to the sender.
  struct sr_rt *longest_match = find_longest_match(sr, iphdr->ip_src);
  if (!longest_match) {
    fprintf(stderr, "routing table entry for closest ip address not found...");
    return;
  }

  // get reference to destination interface by name.
  struct sr_if *dest_if = sr_get_interface(sr, longest_match->interface);

  // divide into all icmp message types and handle them accordingly.
  switch(type):
    case echo_reply: {
      /* set ethernet header source & destination MAC to all 0s */
      memset(ehdr->ether_dhost, 0, ETHER_ADDR_LEN)
      memset(ehdr->ether_shost, 0, ETHER_ADDR_LEN)

      /* swap the dst and src ip addresses of ip header*/
      uint32_t temp = iphdr->ip_dst;
      iphdr->ip_dst = iphdr->ip_src;
      iphdr->ip_src = temp;

      /*construct ICMP Header -> type = 0, code = 0*/
      sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      icmp_hdr->icmp_type = type;
      icmp_hdr->icmp_code = code;
      
      icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));

      send_packet(sr, packet, len, dest_if, longest_match->gw.s_addr);
      break;
    }


  return;
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */

} /* end sr_ForwardPacket */
