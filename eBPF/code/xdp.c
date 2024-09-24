#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
  - Check if packet contains INT headers
  - Store INT data in the map
  - Remove INT headers from the packet
  - Collect data from the host and store it on the map

  Received packet: Eth, int_header, int_trace, ipv4, tcp/udp, rpc
  Outgoing packet: Eth, ipv4, tcp/udp, rpc
*/


SEC("xdp")
int xdp_process_int(struct xdp_md *ctx) {

  bpf_custom_printk("\n XDP start\n");

  __u64 start_time = bpf_ktime_get_ns();

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  int ret = 0;
  int rpc_id = 0;
  int int_offset = 0;

  struct ethhdr *eth;
  eth = data;

	if ((eth + 1) > data_end)
		return XDP_PASS;

  //Check if packet contains INT headers
  if (bpf_ntohs(eth->h_proto) != TYPE_INT_HEADER){
  	bpf_custom_printk("Packet without INT header\n");
  	return XDP_PASS;
  }

  struct int_header *int_header;
  int_header = (struct int_header *) (eth + 1);
  if((int_header + 1) > data_end)
    return XDP_PASS;

  if (be32toh(int_header->qtd_traces) < 1 || be32toh(int_header->qtd_traces) > MAX_HOPS)
  return XDP_PASS;


  //find rpc_id
  unsigned int offset = 0;
  offset += sizeof(struct ethhdr);
  offset += SIZE_INT_HEADER + (be32toh(int_header->qtd_traces) * SIZE_INT_TRACE);
  
  struct iphdr *ip;
  ip = (struct iphdr *) (data + offset);
  if ((ip + 1) > data_end)
    return XDP_PASS;
  
  if(ip->protocol == TYPE_TCP) {
    offset += sizeof(struct iphdr) + sizeof(struct tcphdr);
  }

  if(ip->protocol == TYPE_UDP) {
    offset += sizeof(struct iphdr) + sizeof(struct udphdr);
  }

  struct rpc *rpc;
  rpc = (struct rpc *) (data + offset);
  if ((rpc + 1) > data_end)
    return XDP_PASS;

  rpc_id = be32toh(rpc->id);

  if (rpc_id == 0)
      return XDP_PASS;

  //Collect data from the host
  __u64 ts_init;
  __u64 ts = 0;
  __u64 count_req;

  struct tx_req *tx_req;
  tx_req = bpf_map_lookup_elem(&map_tx_req, &rpc_id);

  if (tx_req) {
    tx_req->count += 1;
    count_req = tx_req->count;
    ts_init = tx_req->ts_init;
  }else {
    ts = bpf_ktime_get_ns();
    ts_init = ts;
    count_req = 1;
    struct tx_req tx_req_a;
    tx_req_a.count = 1;
    tx_req_a.ts_init = ts;
    bpf_map_update_elem(&map_tx_req, &rpc_id, &tx_req_a, BPF_ANY);
  }

  //Stores MAP with INT data
  ret = bpf_map_update_elem(&map_int_header, &rpc_id, int_header, BPF_ANY);

  struct int_trace *int_trace1;
  struct int_trace int_trace1_map;
  struct map_key map_key;
  int_offset += (int)sizeof(struct int_header);
  int_trace1 = (struct int_trace *)(int_header + 1);

  #pragma clang loop unroll (full)
  for (int i = 0 ; i < MAX_HOPS ; i++) {
    if(i < be32toh(int_header->qtd_traces)) {

      int_offset += sizeof(struct int_trace);

      if((int_trace1 + 1) > data_end)
        return XDP_PASS;

      __builtin_memcpy(&int_trace1_map, int_trace1, sizeof(struct int_trace));

      map_key.rpc_id = rpc_id;
      map_key.seq = i;
      ret = bpf_map_update_elem(&map_int_trace, &map_key, &int_trace1_map, BPF_ANY);
      int_trace1 = (struct int_trace *) (int_trace1 + 1);
    } else {
      break;
    }
  }

  //Remove INT headers from the packet

  // Make a copy of the Ethernet header
  struct ethhdr eth_cpy;
  __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

  //adjusts the packet size (at the beginning)
  ret = bpf_xdp_adjust_head(ctx, int_offset);  

  //updates pointer to start and end of packet
  data_end = (void *)(long) ctx->data_end;
  data = (void *)(long) ctx->data;

  eth = data;
  if ((eth + 1) > data_end)
    return XDP_PASS;

  // Copy back the Ethernet header and update the protocol type
  __builtin_memcpy(eth, &eth_cpy, sizeof(eth_cpy));
  eth->h_proto = bpf_htons(TYPE_IPV4);

  
  //Stores MAP with server data  
  struct int_host int_host;
  memset(&int_host, 0, sizeof(int_host));
  int_host.tx_reqs = 1;
  int_host.time_reqs = ts;

  ret = bpf_map_update_elem(&map_int_host, &rpc_id, &int_host, BPF_ANY);

  __u64 end_time = bpf_ktime_get_ns();
  __u64 time_diff = (end_time - start_time);

  bpf_custom_printk("\n XDP_END rpc->id; %llu; %llu; \n", rpc_id, time_diff);
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
