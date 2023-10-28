#include "lookup.h"
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

using namespace std;
std::vector<RoutingTableEntry> table;

void update(bool insert, const RoutingTableEntry entry) {
  // TODO
  if (insert) {
    for (int i = 0; i < table.size(); i++) {
      if (entry.addr == table[i].addr && entry.len == table[i].len) {
        table[i] = entry;
        return;
      }
    }
    table.insert(table.end(), entry);
  } else {
    for (int i = 0; i < table.size(); i++) {
      if (entry.addr == table[i].addr && entry.len == table[i].len) {
        table.erase(table.begin() + i);
        return;
      }
    }
  }
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  // TODO
  int index = -1;
  int max = -1;
  for (int i = 0; i < table.size(); i++) {
    in6_addr dest = table[i].addr;
    int len = table[i].len;
    in6_addr mask = len_to_mask(len);
    in6_addr tmp = addr;
    bool match = true;
    for (int j = 0; j < 4; j++) {
      dest.s6_addr32[j] = dest.s6_addr32[j] & mask.s6_addr32[j];
      tmp.s6_addr32[j] = addr.s6_addr32[j] & mask.s6_addr32[j];
      if (dest.s6_addr32[j] != tmp.s6_addr32[j]) {
        match = false;
        break;
      }
    }
    bool all_zero = true;
    for (int j = 0; j < 4; j++) {
      if (table[i].addr.s6_addr32[j] != 0) {
        all_zero = false;
        break;
      }
    }
    if (all_zero && len == 0) {
      match = true;
    }
    if (match && len > max) {
      index = i;
      max = len;
    }
  }
  if (index >= 0) {
    *nexthop = table[index].nexthop;
    *if_index = table[index].if_index;
    return true;
  }
  return false;
}

int mask_to_len(const in6_addr mask) {
  // TODO
  int len = 0;
  for (int i = 0; i < 4; i++) {
    for (int j = 31; j >= 0; j--) {
      if (ntohl(mask.s6_addr32[i]) & (1 << j)) {
        len++;
      } else {
        if (ntohl(mask.s6_addr32[i]) & (1 << j - 1)) {
          return -1;
        } else {
          return len;
        }
      }
    }
  }
  return len;
}

in6_addr len_to_mask(int len) {
  // TODO
  if (len < 0 || len > 128) {
    return in6_addr{0};
  } else {
    in6_addr mask;
    for (int i = 0; i < 4; i++) {
      if (len >= 32) {
        mask.s6_addr32[i] = 0xffffffff;
        len -= 32;
      } else {
        if (len) {
          mask.s6_addr32[i] = htonl(0xffffffff - (1 << (32 - len)) + 1);
          len = 0;
        } else {
          mask.s6_addr32[i] = 0x00000000;
        }
      }
    }
    return mask;
  }
}
