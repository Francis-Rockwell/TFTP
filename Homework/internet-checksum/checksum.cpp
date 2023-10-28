#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

  int result = 0;
  for (int i = 0; i < 8; i++) {
    result += ntohs(ip6->ip6_dst.s6_addr16[i]);
  }
  for (int i = 0; i < 8; i++) {
    result += ntohs(ip6->ip6_src.s6_addr16[i]);
  }

  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP) {
    // UDP
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    // length: udp->uh_ulen
    // checksum: udp->uh_sum

    short length = ntohs(udp->uh_ulen);
    unsigned short *ptr = (unsigned short *)udp;

    int check = result;
    check += length;
    check += 17;
    while (length > 1) {
      check += ntohs(*ptr);
      ptr++;
      length -= 2;
    }
    if (length > 0) {
      check += ntohs((*(unsigned char *)ptr));
    }
    while ((check >> 16)) {
      check = (check & 0xffff) + (check >> 16);
    }

    length = ntohs(udp->uh_ulen);
    ptr = (unsigned short *)udp;
    short copy = udp->uh_sum;
    udp->uh_sum = 0;
    result += length;
    result += 17;
    while (length > 1) {
      result += ntohs(*ptr);
      ptr++;
      length -= 2;
    }
    if (length > 0) {
      result += ntohs((*(unsigned char *)ptr));
    }
    while ((result >> 16)) {
      result = (result & 0xffff) + (result >> 16);
    }
    result = ~result;
    if ((unsigned short)result == 0x0000) {
      udp->uh_sum = 0xffff;
    } else {
      udp->uh_sum = htons((unsigned short)result);
    }

    if ((unsigned short)copy == 0x0000) {
      return false;
    } else if ((unsigned short)check == 0xffff) {
      return true;
    } else {
      return false;
    }

  } else if (nxt_header == IPPROTO_ICMPV6) {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum

    short length = len - sizeof(struct ip6_hdr);
    unsigned short *ptr = (unsigned short *)icmp;

    int check = result;
    check += length;
    check += 58;
    while (length > 1) {
      check += ntohs(*ptr);
      ptr++;
      length -= 2;
    }
    if (length > 0) {
      check += ntohs((*(unsigned char *)ptr));
    }
    while ((check >> 16)) {
      check = (check & 0xffff) + (check >> 16);
    }

    length = len - sizeof(struct ip6_hdr);
    ptr = (unsigned short *)icmp;
    short copy = icmp->icmp6_cksum;
    icmp->icmp6_cksum = 0;
    result += length;
    result += 58;
    while (length > 1) {
      result += ntohs(*ptr);
      ptr++;
      length -= 2;
    }
    if (length > 0) {
      result += ntohs((*(unsigned char *)ptr));
    }
    while ((result >> 16)) {
      result = (result & 0xffff) + (result >> 16);
    }
    result = ~result;
    icmp->icmp6_cksum = ntohs((unsigned short)result);

    if ((unsigned short)check == 0xffff ||
        ((unsigned short)copy == 0xffff && (unsigned short)result == 0x0000)) {
      return true;
    } else {
      return false;
    }

  } else {
    assert(false);
  }
  return true;
}
