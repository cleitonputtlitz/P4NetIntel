#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "headers.h"

/*
  This code performs the following actions:
  - Check if RPC.id contains INT headers stored in map
  - Add INT headers to the packet
  - Add host data to the packet
  - Remove collected data from the map

  Received packet: Eth, ipv4, tcp/udp, rpc
  Outgoing packet: Eth, int_header, int_trace, int_host, ipv4, tcp/udp, rpc
*/

SEC("tc")
int tc_process_int(struct __sk_buff *skb) {

  bpf_custom_printk("\n TC start\n");

  __u64 start_time = bpf_ktime_get_ns();

  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  int ret = 0;
  int offset = 0;
  int key = 0;
  int rpc_id = 0;
  __u64 flags;

  struct ethhdr *eth = data;
  if ((eth + 1) > data_end)
    return TC_ACT_OK;

  struct iphdr *iph;
  iph = (struct iphdr *)(eth + 1);
  if ((iph + 1) > data_end) {
    return TC_ACT_OK;
  }

  if(iph->protocol == TYPE_TCP) {
    offset += sizeof(struct iphdr) + sizeof(struct tcphdr);
  }

  if(iph->protocol == TYPE_UDP) {
    offset += sizeof(struct iphdr) + sizeof(struct udphdr);
  }  

  offset += sizeof(struct ethhdr);

  struct rpc *rpc;
  rpc = (struct rpc *) (data + offset);
  if ((rpc + 1) > data_end)
    return 0;


  rpc_id = be32toh(rpc->id);

  if(rpc_id == 0)
      return TC_ACT_OK;

  
  iph = (struct iphdr *)(eth + 1);
  if ((iph + 1) > data_end) {
    return TC_ACT_OK;
  }

  //Make a copy of the Ethernet and IP header
  struct ethhdr eth_cpy;
  __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
  struct iphdr iph_cpy;
  __builtin_memcpy(&iph_cpy, iph, sizeof(iph_cpy));


  //RPC.id used to fetch data stored in the map
  key = rpc_id;

  struct int_header *int_header_map = bpf_map_lookup_elem(&map_int_header, &key);
  ret = bpf_map_delete_elem(&map_int_header, &key);

  if(!int_header_map) {
    bpf_custom_printk("FAILED when fetching data from map int_header \n");
    return TC_ACT_OK;
  }

  if (be32toh(int_header_map->qtd_traces) < 1 || be32toh(int_header_map->qtd_traces) > MAX_HOPS) {
    bpf_custom_printk("FAILED when fetching data from map int_header == 0 \n");
    return TC_ACT_OK;
  }

  //Add space at the beginning of the packet
  int qtd_traces = be32toh(int_header_map->qtd_traces);

  int int_offset = sizeof(struct int_header) + (qtd_traces * SIZE_INT_TRACE) + sizeof(struct int_host);

  //flags = BPF_F_ADJ_ROOM_NO_CSUM_RESET | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
  //only works when it is eth|ip
  ret = bpf_skb_adjust_room(skb, int_offset, BPF_ADJ_ROOM_MAC, 0);

  eth_cpy.h_proto = bpf_htons(TYPE_INT_HEADER);
  offset = 0;

  //Copy back the Ethernet header
  ret = bpf_skb_store_bytes(skb, offset, &eth_cpy, sizeof(struct ethhdr), 0);
  offset = sizeof(struct ethhdr);

  //Write int_header
  ret = bpf_skb_store_bytes(skb, offset, int_header_map, sizeof(struct int_header), 0);
  offset += sizeof(struct int_header);

  struct int_trace *int_trace_map;
  struct int_trace int_trace1;
  struct map_key map_key;

  //Write int_trace
  #pragma clang loop unroll (full)
  for (int i = 0 ; i < MAX_HOPS ; i++) {
      if(i < be32toh(int_header_map->qtd_traces)) {

        map_key.rpc_id = key;
        map_key.seq = i;

        int_trace_map = bpf_map_lookup_elem(&map_int_trace, &map_key);
        ret = bpf_map_delete_elem(&map_int_trace, &map_key);
        if(int_trace_map){
            
           __builtin_memcpy(&int_trace1, int_trace_map, sizeof(struct int_trace));

          if(i == be32toh(int_header_map->qtd_traces)-1)
              int_trace1.next_proto = bpf_htons(TYPE_INT_HOST);

          ret = bpf_skb_store_bytes(skb, offset, &int_trace1, sizeof(struct int_trace),0);

          offset += sizeof(struct int_trace);
        }
      } else {
        break;
      }
  }

  //search int_host
  struct int_host *int_host = bpf_map_lookup_elem(&map_int_host, &key);
  ret = bpf_map_delete_elem(&map_int_host, &key);
  bpf_custom_printk("Ret bpf_map_delete_elem map_int_host %d \n", ret);

  //Calculates the request time
  __u64 ts = bpf_ktime_get_ns();
  if(int_host){
      int_host->time_reqs = ts - int_host->time_reqs;
      int_host->next_proto = bpf_htons(TYPE_IPV4);
  } else {
    return TC_ACT_OK;
  }

  //Write int_host
  ret = bpf_skb_store_bytes(skb, offset, int_host, sizeof(struct int_host), 0);
  offset += sizeof(struct int_host);


  __u64 end_time = bpf_ktime_get_ns();
  __u64 time_diff = (end_time - start_time);
  
  bpf_custom_printk("\n TC_END rpc->id; %llu; %llu; \n", rpc_id, time_diff);

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
