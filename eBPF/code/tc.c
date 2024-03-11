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
  Verificar se o RPC.id contém cabeçalhos INT armazenado no map
  Adicionar os cabeçalhos INT no pacote
  Adicionar os dados do host no pacote
  Remover os dados coletados do map

  Pacote entrada: Eth, ipv4, udp, rpc
  Pacote saida: Eth, int_header, int_trace, int_host, ipv4, udp, rpc
*/
static inline
int find_rpc_id(struct __sk_buff *skb) {

    //Eth, int_header, int_trace...int_trace, IP, UDP, RPC, raw
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    int offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

    struct rpc *rpc;
    rpc = (struct rpc *) (data + offset);
    if ((rpc + 1) > data_end)
      return 0;

    bpf_custom_printk("rpc->id %lu\n", be32toh(rpc->id));
    return rpc->id;
}

SEC("tc")
int tc_process_int(struct __sk_buff *skb) {

  __u64 start_time = bpf_ktime_get_ns();

  bpf_custom_printk("\n TC INICIO\n");
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

  //Se o pacote não contem cabeçalhos RPC
  //bpf_custom_printk("Protocolo Ethernet: %d\n", bpf_ntohs(eth->h_proto));
/*  if (bpf_ntohs(eth->h_proto) != TYPE_RPC){
  	return TC_ACT_OK;
  }
*/

  offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

  struct rpc *rpc;
  rpc = (struct rpc *) (data + offset);
  if ((rpc + 1) > data_end)
    return 0;

  //bpf_custom_printk("rpc->id %lu \n", rpc->id);
  rpc_id = rpc->id;

  if(rpc_id == 0)
      return TC_ACT_OK;

  struct iphdr *iph;
  iph = (struct iphdr *)(eth + 1);
  if ((iph + 1) > data_end) {
    return TC_ACT_OK;
  }

  //Faz uma cópia do cabeçalho Ethernet, IP
  struct ethhdr eth_cpy;
  __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
  struct iphdr iph_cpy;
  __builtin_memcpy(&iph_cpy, iph, sizeof(iph_cpy));


  //RPC.id usado para buscar os dados armazenados no map
  key = rpc_id;

  struct int_header *int_header_map = bpf_map_lookup_elem(&map_int_header, &key);
  ret = bpf_map_delete_elem(&map_int_header, &key);
  bpf_custom_printk("Ret map_int_header bpf_map_delete_elem %d \n", ret);

  if(!int_header_map) {
    bpf_custom_printk("FALHA ao buscar dados do map int_header \n");
    return TC_ACT_OK;
  }

  if (be32toh(int_header_map->qtd_traces) < 1 || be32toh(int_header_map->qtd_traces) > MAX_HOPS) {
    bpf_custom_printk("FALHA ao buscar dados do map int_header == 0 \n");
    return TC_ACT_OK;
  }

  //Adiciona espaço no início do pacote
  int qtd_traces = be32toh(int_header_map->qtd_traces);
  //bpf_custom_printk("qtd_traces %d\n", qtd_traces);

  int int_offset = sizeof(struct int_header) + (qtd_traces * SIZE_INT_TRACE) + sizeof(struct int_host);

  //flags = BPF_F_ADJ_ROOM_NO_CSUM_RESET | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
  //só funciona quando for eth+ip
  ret = bpf_skb_adjust_room(skb, int_offset, BPF_ADJ_ROOM_MAC, 0);
  bpf_custom_printk("Ret bpf_skb_adjust_room %d offset %d \n", ret, int_offset);

  //Altera o protocolo do cabeçalho Ethernet
  eth_cpy.h_proto = bpf_htons(TYPE_INT_HEADER);
  offset = 0;

  //grava eth
  ret = bpf_skb_store_bytes(skb, offset, &eth_cpy, sizeof(struct ethhdr), 0);
  offset = sizeof(struct ethhdr);

  //Grava int_header
  ret = bpf_skb_store_bytes(skb, offset, int_header_map, sizeof(struct int_header), 0);
  offset += sizeof(struct int_header);

  struct int_trace *int_trace_map;
  struct int_trace int_trace1;
  struct map_key map_key;

  //grava int_trace
  #pragma clang loop unroll (full)
  for (int i = 0 ; i < MAX_HOPS ; i++) {
      if(i < be32toh(int_header_map->qtd_traces)) {

        map_key.rpc_id = key;
        map_key.seq = i;

        int_trace_map = bpf_map_lookup_elem(&map_int_trace, &map_key);
        ret = bpf_map_delete_elem(&map_int_trace, &map_key);
        if(int_trace_map){
                              //destino       //origem
           __builtin_memcpy(&int_trace1, int_trace_map, sizeof(struct int_trace));

          if(i == be32toh(int_header_map->qtd_traces)-1) //ultimo
              int_trace1.next_proto = bpf_htons(TYPE_INT_HOST);

          ret = bpf_skb_store_bytes(skb, offset, &int_trace1, sizeof(struct int_trace),0);
          bpf_custom_printk("Ret add INT swid: %lu ret: %d \n",be32toh(int_trace1.swid), ret);

          offset += sizeof(struct int_trace);
        }
      } else {
        break;
      }
  }

  //Busca int_host
  struct int_host *int_host = bpf_map_lookup_elem(&map_int_host, &key);
  ret = bpf_map_delete_elem(&map_int_host, &key);
  bpf_custom_printk("Ret bpf_map_delete_elem map_int_host %d \n", ret);

  //Calcula o tempo da requisiçao
  __u64 ts = bpf_ktime_get_ns();
  if(int_host){
      int_host->time_reqs = ts - int_host->time_reqs;
      int_host->next_proto = bpf_htons(TYPE_IPV4);
  } else {
    return TC_ACT_OK;
  }

  //Grava int_host
  ret = bpf_skb_store_bytes(skb, offset, int_host, sizeof(struct int_host), 0);
  offset += sizeof(struct int_host);


  __u64 end_time = bpf_ktime_get_ns();
  __u64 time_diff = (end_time - start_time);
  bpf_custom_printk("\n TC_FIM rpc->id; %lu; %llu; %llu;\n", rpc_id, start_time, end_time);
  bpf_custom_printk("\n TC_TIME rpc->id; %lu; %llu; \n", rpc_id, time_diff);

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
