#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void create_ethernet_header(sr_ethernet_hdr_t *e_hdr, uint8_t *new_packet,
                            uint8_t *src_e_addr, uint8_t *dest_e_addr,
                            uint16_t ether_type) {
  sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t *)new_packet;
  memcpy(new_e_hdr->ether_shost, src_e_addr, ETHER_ADDR_LEN);
  memcpy(new_e_hdr->ether_dhost, dest_e_addr, ETHER_ADDR_LEN);
  new_e_hdr->ether_type = ether_type;
}

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

void send_packet(struct sr_instance *sr, uint8_t *p_frame, unsigned int len,
                 struct sr_if *dest_if, uint32_t dest_ip) {

  /* check sr->cache to see if arp has been cached then handle accordingly.
   */
  struct sr_arpentry *cached_ip = sr_arpcache_lookup(&sr->cache, dest_ip);
  if (cached_ip) {
    /* ip has been cached to a MAC already
     */
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)p_frame;

    /* set destination MAC to mapped MAC
     */
    memcpy(ehdr->ether_dhost, cached_ip->mac, ETHER_ADDR_LEN);

    /* set source MAC to destination interface's MAC
     */
    memcpy(ehdr->ether_shost, dest_if->addr, ETHER_ADDR_LEN);

    sr_send_packet(sr, p_frame, len, dest_if->name);
    free(cached_ip);
  } else {
    /* not cached; thus, send ARP req
     */
    struct sr_arpreq *req =
        sr_arpcache_queuereq(&sr->cache, dest_ip, p_frame, len, dest_if->name);
    handle_arpreq(sr, req);
  }

  return;
}

void send_icmp(struct sr_instance *sr, uint8_t *p_frame, unsigned int len,
               uint8_t type, uint8_t code) {
  /* p_frame is packet's raw frame.
   point structs to ethernet, ip headers accordingly.
   */
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)p_frame;
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(p_frame + sizeof(sr_ethernet_hdr_t));

  /* need to find destination interface
     find longest matching prefix of src ip since icmp goes back to the sender.
  */
  struct sr_rt *longest_match = find_longest_match(sr, iphdr->ip_src);
  if (!longest_match) {
    fprintf(stderr, "routing table entry for closest ip address not found...");
    return;
  }

  /* get reference to destination interface by name.
   */
  struct sr_if *dest_if = sr_get_interface(sr, longest_match->interface);

  /* divide into all icmp message types and handle them accordingly.
   */

  switch (type) {
  
  case echo_reply: {
    /* set ehdr source MAC and dest MAC to all 0s
     
    memset(ehdr->ether_shost, 0, ETHER_ADDR_LEN);
    memset(ehdr->ether_dhost, 0, ETHER_ADDR_LEN);*/
    memcpy(ehdr->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ehdr->ether_shost, dest_if->addr, ETHER_ADDR_LEN);


    /* swap destination ip and source ip of iphdr since the packet is being sent
      back
    */
    uint32_t temp = iphdr->ip_dst;
    iphdr->ip_dst = iphdr->ip_src;
    iphdr->ip_src = temp;

    /* construct icmp header */
    sr_icmp_hdr_t *icmphdr =
        (sr_icmp_hdr_t *)(p_frame + sizeof(sr_ethernet_hdr_t) +
                          sizeof(sr_ip_hdr_t));
    icmphdr->icmp_type = type;
    icmphdr->icmp_code = code;
    icmphdr->icmp_sum = 0;
    icmphdr->icmp_sum =
        cksum(icmphdr, ntohs(iphdr->ip_len) - (iphdr->ip_hl * 4));

    send_packet(sr, p_frame, len, dest_if, longest_match->gw.s_addr);
    break;
  }
  case time_exceeded:
  case dest_unreachable: {
    unsigned int new_len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                            sizeof(sr_icmp_t3_hdr_t));
    uint8_t *new_frame = malloc(new_len);

    /* make ethernet header */
    sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *)new_frame;
    /* make ip header */
    sr_ip_hdr_t *new_iphdr =
        (sr_ip_hdr_t *)(new_frame + sizeof(sr_ethernet_hdr_t));
    /* make icmp type 3 header */
    sr_icmp_t3_hdr_t *new_icmphdr =
        (sr_icmp_t3_hdr_t *)(new_frame + sizeof(sr_ethernet_hdr_t) +
                             (iphdr->ip_hl * 4));

    /* set new ethernet header source and dest MAC to 0s */
    memset(new_ehdr->ether_shost, 0, ETHER_ADDR_LEN);
    memset(new_ehdr->ether_dhost, 0, ETHER_ADDR_LEN);
    /* protocol is IP */
    new_ehdr->ether_type = htons(ethertype_ip);

    /* set up ip header */
    new_iphdr->ip_v = 4;
    new_iphdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    new_iphdr->ip_tos = 0;
    new_iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_iphdr->ip_id = htons(0);
    new_iphdr->ip_off = htons(IP_DF);
    new_iphdr->ip_ttl = 255;
    new_iphdr->ip_p = ip_protocol_icmp;
    /* if code is 3, set src IP to received packet's dest_ip */
    new_iphdr->ip_src = (code == port) ? iphdr->ip_dst : dest_if->ip;
    new_iphdr->ip_dst = iphdr->ip_src;
    new_iphdr->ip_sum = 0;
    new_iphdr->ip_sum = cksum(new_iphdr, sizeof(sr_ip_hdr_t));


    /* set up new_icmphdr */
    new_icmphdr->icmp_type = type;
    new_icmphdr->icmp_code = code;
    new_icmphdr->unused = 0;
    new_icmphdr->next_mtu = 0;
    memcpy(new_icmphdr->data, iphdr, ICMP_DATA_SIZE);
    new_icmphdr->icmp_sum = 0;
    new_icmphdr->icmp_sum = cksum(new_icmphdr, sizeof(sr_icmp_t3_hdr_t));

    send_packet(sr, new_frame, new_len, dest_if, longest_match->gw.s_addr);
    free(new_frame);
    break;
  }
  }
}

void arp_handler(struct sr_instance *sr, uint8_t *p_frame, unsigned int len,
                 char *interface) {
  /* store contents of the ARP header. */
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(p_frame + sizeof(sr_ethernet_hdr_t));

  /* verify format */
  if (ntohs(arphdr->ar_hrd) != arp_hrd_ethernet) {
    fprintf(stderr, "arp_handler: packet is not an ethernet frame.\n");
    return;
  }

  /*  verify ethernet protocol type */
  if (ntohs(arphdr->ar_pro) != ethertype_ip) {
    fprintf(stderr, "arp_handler: packet is not an IP packet.\n");
    return;
  }

  /*  verify that the router has the destination IP listed */
  int if_exists = 0;
  struct sr_if *if_iterator = sr->if_list;
  while (if_iterator) {
    if (if_iterator->ip == arphdr->ar_tip) {
      if_exists = 1;
    }
    if_iterator = if_iterator->next;
  }

  if (!if_exists) {
    fprintf(stderr,
            "arp_handler: Destination IP not listed on this router...\n");
    return;
  }

  switch (ntohs(arphdr->ar_op)) {
  case arp_op_request: {
    struct sr_if *src_if = sr_get_interface(sr, interface);
    uint8_t *arpreq = malloc(len);
    memcpy(arpreq, p_frame, len);

    /* make ethernet hdr */
    sr_ethernet_hdr_t *arpreq_ehdr = (sr_ethernet_hdr_t *)arpreq;

    memcpy(arpreq_ehdr->ether_dhost, arpreq_ehdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(arpreq_ehdr->ether_shost, src_if, ETHER_ADDR_LEN);

    /* make ARP hdr */
    sr_arp_hdr_t *arpreq_hdr =
        (sr_arp_hdr_t *)(arpreq + sizeof(sr_ethernet_hdr_t));
    arpreq_hdr->ar_op = htons(arp_op_reply);
    /* set sender MAC to the src_if MAC */
    memcpy(arpreq_hdr->ar_sha, src_if->addr, ETHER_ADDR_LEN);
    /* set sender IP to the src_if IP */
    arpreq_hdr->ar_sip = src_if->ip;
    /* set destination MAC to be packet sender's MAC */
    memcpy(arpreq_hdr->ar_tha, arphdr->ar_sha, ETHER_ADDR_LEN);
    /* set target IP to be the packet sender's IP */
    arpreq_hdr->ar_tip = arphdr->ar_sip;

    send_packet(sr, arpreq, len, src_if, arphdr->ar_sip);
    free(arpreq);

    break;
  }
  case arp_op_reply: {
    struct sr_arpreq *cached =
        sr_arpcache_insert(&sr->cache, arphdr->ar_sha, arphdr->ar_sip);

    if (cached) {
      struct sr_packet *cached_packet = cached->packets;

      struct sr_if *src_if;
      sr_ethernet_hdr_t *ehdr;

      while (cached_packet) {
        src_if = sr_get_interface(sr, cached_packet->iface);
        if (src_if) {
          ehdr = (sr_ethernet_hdr_t *)(cached_packet->buf);
          memcpy(ehdr->ether_dhost, arphdr->ar_sha, ETHER_ADDR_LEN);
          memcpy(ehdr->ether_shost, src_if->addr, ETHER_ADDR_LEN);

          sr_send_packet(sr, cached_packet->buf, cached_packet->len,
                         cached_packet->iface);
        }
        cached_packet = cached_packet->next;
      }
      sr_arpreq_destroy(&sr->cache, cached);
    }
    break;
  }
  }
}

void ip_handler(struct sr_instance *sr, uint8_t *p_frame, unsigned int len,
                char *interface) {
  /* store contents of the packet frame */
  uint8_t *payload = (p_frame + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)payload;

  /* sanity check the ip frame */
  uint16_t temp_checksum = iphdr->ip_sum;
  iphdr->ip_sum = 0;
  uint16_t true_checksum = cksum(iphdr, iphdr->ip_hl * 4);
  if (temp_checksum != true_checksum) {
    fprintf(stderr, "ip_handler: checksum doesn't match\n");
    return;
  }

  if (iphdr->ip_len < 20) {
    fprintf(stderr, "ip_handler: minimum length req not met\n");
    return;
  }

  printf("IP Header:\n");
    printf("\tVersion: %d\n \tHeader Length: %d\n \tType of Service: %d\n \tLength: %d\n \tID: %d\n \tOffset: %d\n \tTTL: %d\n \tProtocol: %d\n \tChecksum: %d\n \tSource: ", 
            iphdr->ip_v, iphdr->ip_hl, iphdr->ip_tos, iphdr->ip_len, iphdr->ip_id, iphdr->ip_off, iphdr->ip_ttl, iphdr->ip_p, iphdr->ip_sum);
    print_addr_ip_int(iphdr->ip_src);
    printf("\n\tDestination: ");
    print_addr_ip_int(iphdr->ip_dst);

  /* check if packet's destination is this router */

  int if_exists = 0;
  struct sr_if *if_iterator = sr->if_list;
  while (if_iterator) {
    if (if_iterator->ip == iphdr->ip_dst) {
      if_exists = 1;
    }
    if_iterator = if_iterator->next;
  }

  if (!if_exists) {
    /* packet's dest is not this router. */

    /* construct IP hdr */
    sr_ip_hdr_t *new_iphdr =
        (sr_ip_hdr_t *)(p_frame + sizeof(sr_ethernet_hdr_t));

    /* decrease ttl */
    new_iphdr->ip_ttl--;
    if (new_iphdr->ip_ttl == 0) {
      send_icmp(sr, p_frame, len, (uint8_t)time_exceeded, (uint8_t)time_exceeded_code);
      return;
    }

    new_iphdr->ip_sum = 0;
    new_iphdr->ip_sum = cksum(new_iphdr, new_iphdr->ip_hl * 4);

    struct sr_rt *rt_entry = find_longest_match(sr, new_iphdr->ip_dst);
    if (!rt_entry) {
      /* dest IP not in routing table */
      send_icmp(sr, p_frame, len, (uint8_t)dest_unreachable, (uint8_t)net);
      return;
    }
    struct sr_if *dest_if = sr_get_interface(sr, rt_entry->interface);
    if (!dest_if) {
      fprintf(stderr, "ip_handler: interface not found...\n");
      return;
    }
    send_packet(sr, p_frame, len, dest_if, rt_entry->gw.s_addr);
  } else {
    /* packet reached its destination */

    switch (iphdr->ip_p) {
    case ip_protocol_icmp: {
      /* packet is an icmp msg */
      sr_icmp_hdr_t *icmphdr =
          (sr_icmp_hdr_t *)(p_frame + sizeof(sr_ethernet_hdr_t) +
                            sizeof(sr_ip_hdr_t));

      if (icmphdr->icmp_type == echo_request) {
        send_icmp(sr, p_frame, len, (uint8_t)echo_reply, (uint8_t)0);
      }
      break;
    }
    case ip_protocol_tcp:
    case ip_protocol_udp: {
      /* port is unreachable */
      send_icmp(sr, p_frame, len, (uint8_t)dest_unreachable, (uint8_t)port);
      break;
    }
    }
  }
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

  /* fill in code here */

  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Ethernet header does not satisfy length requirement...");
    return;
  }

  uint16_t eth_type = ethertype(packet);

  if (eth_type == ethertype_ip) {
    printf("<- Received IP packet of length %d ->\n", len);
    ip_handler(sr, packet, len, interface);
  } else if (eth_type == ethertype_arp) {
    printf("<- Received ARP packet of length %d ->\n", len);
    arp_handler(sr, packet, len, interface);
  }
} /* end sr_ForwardPacket */
