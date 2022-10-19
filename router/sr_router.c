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

void create_ethernet_header (sr_ethernet_hdr_t * e_hdr, uint8_t * new_packet, uint8_t *src_e_addr,
                            uint8_t *dest_e_addr, uint16_t ether_type) {
    sr_ethernet_hdr_t *new_e_hdr = (sr_ethernet_hdr_t *) new_packet;
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

  // check sr->cache to see if arp has been cached then handle accordingly.
  struct sr_arpentry *cached_ip = sr_arpcache_lookup(&sr->cache, dest_ip);
  if (cached_ip) {
    // ip has been cached to a MAC already
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)p_frame;

    // set destination MAC to mapped MAC
    memcpy(ehdr->ether_dhost, cached_ip->mac, ETHER_ADDR_LEN);

    // set source MAC to destination interface's MAC
    memcpy(ehdr->ether_shost, dest_if->addr, ETHER_ADDR_LEN);

    sr_send_packet(sr, p_frame, len, dest_if->name);
    free(cached_ip);
  } else {
    // not cached; thus, send ARP req
    struct sr_arpreq *req =
        sr_arpcache_queuereq(&sr->cache, dest_ip, p_frame, len, dest_if->name);
    handle_arpreq(sr, req);
  }

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

  switch (type) {
    case time_exceeded:
    case echo_reply: {
      // set ehdr source MAC and dest MAC to all 0s
      memset(ehdr->ether_shost, 0, ETHER_ADDR_LEN);
      memset(ehdr->ether_dhost, 0, ETHER_ADDR_LEN);

      // swap destination ip and source ip of iphdr since the packet is being sent
      // back
      uint32_t temp = iphdr->ip_dst;
      iphdr->ip_dst = iphdr->ip_src;
      iphdr->ip_src = temp;

      // construct icmp header
      sr_icmp_hdr_t *icmphdr =
          (sr_icmp_hdr_t *)(p_frame + sizeof(sr_ethernet_hdr_t) +
                            sizeof(sr_ip_hdr_t));
      icmphdr->icmp_type = type;
      icmphdr->icmp_code = code;
      icmphdr->icmp_sum =
          cksum(icmphdr, ntohs(iphdr->ip_len) - (iphdr->ip_hl * 4));

      send_packet(sr, p_frame, len, dest_if, longest_match->gw.s_addr);
      break;
    }
    case dest_unreachable: {
      unsigned int new_len = (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                              sizeof(sr_icmp_t3_hdr_t));
      uint8_t *new_frame = malloc(new_len);

      // make ethernet header
      sr_ethernet_hdr_t *new_ehdr = (sr_ethernet_hdr_t *)new_frame;
      // make ip header
      sr_ip_hdr_t *new_iphdr =
          (sr_ip_hdr_t *)(new_frame + sizeof(sr_ethernet_hdr_t));
      // make icmp type 3 header
      sr_icmp_t3_hdr_t *new_icmphdr =
          (sr_icmp_t3_hdr_t *)(new_frame + sizeof(sr_ethernet_hdr_t) +
                              (iphdr->ip_hl * 4));

      // set new ethernet header source and dest MAC to 0s
      memset(new_ehdr->ether_shost, 0, ETHER_ADDR_LEN);
      memset(new_ehdr->ether_dhost, 0, ETHER_ADDR_LEN);
      // protocol is IP
      new_ehdr->ether_type = htons(ethertype_ip);

      // set up ip header
      new_iphdr->ip_v = 4;
      new_iphdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
      new_iphdr->ip_tos = 0;
      new_iphdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      new_iphdr->ip_id = htons(0);
      new_iphdr->ip_off = htons(IP_DF);
      new_iphdr->ip_ttl = 255;
      new_iphdr->ip_p = ip_protocol_icmp;
      // if code is 3, set src IP to received packet's dest_ip
      new_iphdr->ip_src = (code == port) ? iphdr->ip_dst : dest_if->ip;
      new_iphdr->ip_dst = iphdr->ip_src;
      new_iphdr->ip_sum = cksum(new_iphdr, sizeof(sr_ip_hdr_t));

      // set up new_icmphdr
      new_icmphdr->icmp_type = type;
      new_icmphdr->icmp_code = code;
      new_icmphdr->unused = 0;
      new_icmphdr->next_mtu = 0;
      memcpy(new_icmphdr->data, iphdr, ICMP_DATA_SIZE);
      new_icmphdr->icmp_sum = cksum(new_icmphdr, sizeof(sr_icmp_t3_hdr_t));

      send_packet(sr, new_frame, new_len, dest_if, longest_match->gw.s_addr);
      free(new_frame);
      break;
    }
  }
  return;
}

void arp_handler(struct sr_instance *sr, uint8_t *p_frame, unsigned int len,
                char *interface) {

    /* Get ARP header */
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /*Get Ethernet Header*/
    sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*) arp_reply;

    unsigned short arp_opcode = ntohs(arp_hdr->ar_op)

    /*Verify that the destination interface is in our router*/
    struct sr_if *dest_if = sr_get_interface_by_ip(sr, arp_hdr->ar_tip);
    if (!dest_if) {
		fprintf(stderr, "destination IP is not valid");
		return;
    }

    if (arp_opcode == arp_op_request){
        printf("Received ARP request.\n")

        uint8_t *arp_reply = malloc(len);

        /*Create Ethernet Header*/
        create_ethernet_header(e_hdr, arp_reply, dest_if->addr, e_hdr->ether_shost, ethertype_arp)

        /*Create ARP Header*/
        sr_arp_hdr_t arp_hdr = (sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t));
        arp_hdr->ar_op = htons(arp_op_reply);

        /* Swap sender and targer hardware addresses and IP addresses */
        memcpy(arp_hdr->ar_sha, dest_if->addr, ETHER_ADDR_LEN);
        arp_hdr->ar_sip = dest_if->ip;
        memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        arp_hdr->ar_tip = arp_hdr->ar_sip;
        
        send_packet(sr, arp_reply, len, dest_if, arp_hdr->ar_sip);
        free(arp_reply);
        return;

    } else if (arp_opcode == arp_op_reply) {
        printf("Received ARP reply.\n");

        struct sr_arpreq* req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);

		if (req) {
			struct sr_packet *packet = req->packets;

			while(packet) {
				struct sr_if *in_if = sr_get_interface(sr, packet->iface);

				/*Create ethernet header*/
				req_e_hdr = (sr_ethernet_hdr_t *)(packet->buf);
				memcpy(req_e_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
				memcpy(req_e_hdr->ether_shost, in_if->addr, ETHER_ADDR_LEN);

				sr_send_packet(sr, packet->buf, packet->len, packet->iface);

				packet = packet->next
			}
			sr_arpreq_destroy(&sr->cache, cached);
		}
		
        return;
    }

}

void ip_handler(struct sr_instance *sr, uint8_t *p_frame, unsigned int len,
                char *interface) {

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

  if(len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Ethernet header does not satisfy length requirement...");
    return;
  }

  uint16_t eth_type = ethertype(packet)

  if (eth_type == ethertype_ip) {
    ip_handler(sr, packet, len, interface);
  }
  else if (eth_type == ethertype_arp) {
    arp_handler(sr, packet, len, interface);
  }
} /* end sr_ForwardPacket */
