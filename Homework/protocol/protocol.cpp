#include "protocol.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

RipngErrorCode disassemble(const uint8_t *packet, uint32_t len,
                           RipngPacket *output) {
  // TODO
  if (len < 40) {
    return ERR_LENGTH;
  }
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  if (ntohs(ip6->ip6_plen) + 40 != len) {
    return ERR_LENGTH;
  }
  if (ip6->ip6_nxt != 17) {
    return ERR_IPV6_NEXT_HEADER_NOT_UDP;
  }
  if (ntohs(ip6->ip6_plen) < 8) {
    return ERR_LENGTH;
  }
  struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
  if ((ntohs(udp->uh_sport) != 521) || (ntohs(udp->uh_dport) != 521)) {
    return ERR_UDP_PORT_NOT_RIPNG;
  }
  if ((ntohs(udp->uh_ulen) - 8 - 4) % 20) {
    return ERR_LENGTH;
  }
  struct ripng_hdr *ripng = (struct ripng_hdr *)&packet[sizeof(struct ip6_hdr) +
                                                        sizeof(struct udphdr)];
  if (ripng->command != 1 && ripng->command != 2) {
    return ERR_RIPNG_BAD_COMMAND;
  }
  if (ripng->version != 1) {
    return ERR_RIPNG_BAD_VERSION;
  }
  if (ntohs(ripng->zero)) {
    return ERR_RIPNG_BAD_ZERO;
  }
  int count = (ntohs(udp->uh_ulen) - 8 - 4) / 20;
  for (int i = 0; i < count; i++) {
    ripng_rte *rte =
        (ripng_rte *)&packet[sizeof(struct ip6_hdr) + sizeof(struct udphdr) +
                             sizeof(struct ripng_hdr) + sizeof(ripng_rte) * i];
    if (rte->metric == 0xff) {
      if (rte->prefix_len) {
        return ERR_RIPNG_BAD_PREFIX_LEN;
      }
      if (ntohs(rte->route_tag)) {
        return ERR_RIPNG_BAD_ROUTE_TAG;
      }
    } else {
      if (rte->metric < 1 || rte->metric > 16) {
        return ERR_RIPNG_BAD_METRIC;
      }
      if (rte->prefix_len < 0 || rte->prefix_len > 128) {
        return ERR_RIPNG_BAD_PREFIX_LEN;
      }
      if ((len_to_mask(rte->prefix_len) & rte->prefix_or_nh) !=
          rte->prefix_or_nh) {
        return ERR_RIPNG_INCONSISTENT_PREFIX_LENGTH;
      }
    }
  }
  output->command = ripng->command;
  output->numEntries = count;
  for (int i = 0; i < count; i++) {
    output->entries[i] =
        *(ripng_rte *)&packet[sizeof(struct ip6_hdr) + sizeof(struct udphdr) +
                              sizeof(struct ripng_hdr) + sizeof(ripng_rte) * i];
  }
  return RipngErrorCode::SUCCESS;
}

uint32_t assemble(const RipngPacket *ripng, uint8_t *buffer) {
  // TODO
  buffer[0] = ripng->command;
  buffer[1] = 1;
  buffer[2] = 0;
  buffer[3] = 0;
  for (int i = 0; i < ripng->numEntries; i++) {
    for (int j = 0; j < 16; j++) {
      buffer[4 + i * 20 + j] = ripng->entries[i].prefix_or_nh.s6_addr[j];
    }
    uint16_t *ptr = (uint16_t *)&buffer[4 + i * 20 + 16];
    *ptr = ripng->entries[i].route_tag;
    buffer[4 + i * 20 + 18] = ripng->entries[i].prefix_len;
    buffer[4 + i * 20 + 19] = ripng->entries[i].metric;
  }
  return (4 + ripng->numEntries * 20);
}