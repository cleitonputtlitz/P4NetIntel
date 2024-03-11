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
  Verificar se o pacote contém cabeçalhos INT
  Armazenar os dados INT no map
  Remover os cabeçalhos INT do pacote
  Coletar Dados do host e armazenar no map

  Pacote entrada: Eth, int_header, int_trace, ipv4, udp, rpc
  Pacote saida: Eth, rpc, ipv4, udp
*/


SEC("xdp")
int xdp_process_int(struct xdp_md *ctx) {

  bpf_custom_printk("\n XDP INICIO\n");

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

  //Se o pacote não contem cabeçalhos INT
  if (bpf_ntohs(eth->h_proto) != TYPE_INT_HEADER){
  	bpf_custom_printk("Pacote sem cabecalho INT\n");
  	return XDP_PASS;
  }

  struct int_header *int_header;
  int_header = (struct int_header *) (eth + 1);
  if((int_header + 1) > data_end)
    return XDP_PASS;

  //bpf_custom_printk("Qtd INT Header: %d\n", be32toh(int_header->qtd_traces));

  //find_rpc_id
  unsigned int offset = 0;
  offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
  if (be32toh(int_header->qtd_traces) < 1 || be32toh(int_header->qtd_traces) > MAX_HOPS)
    return 0;

  offset += SIZE_INT_HEADER + (be32toh(int_header->qtd_traces) * SIZE_INT_TRACE);

  struct rpc *rpc;
  rpc = (struct rpc *) (data + offset);
  if ((rpc + 1) > data_end)
    return 0;

  rpc_id = rpc->id;

  if (rpc_id == 0)
      return XDP_PASS;

  /******************************* DADOS COLETADOS DO SERVIDOR: *************************************************
      - Taxa de requisiçao
      - Timestamp de chegada da requisiçao
  */

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

  //calcula a taxa de requisiçao
  //1 Segundos = 1000000000 Nanossegundos
  //__u64 ts_now = bpf_ktime_get_ns();
  //__u64 delta = ts_now - ts_init;
  //if(delta != 0) {
    //nao aceita float
    //delta = (int)delta / 0.0000000001;
    //tx_req = (int)count_req / delta;
    //if(tx_req <= 0){
      //count_req = 1;
    //}
  //}

  /*********************************** FIM DA COLETA DOS DADOS DO SERVIDOR ***********************************/


  /**
  *       Salva os dados INT no MAP
  **/

  /*
  struct int_header *int_header;
  int_header = (struct int_header *) (eth + 1);
  if((int_header + 1) > data_end)
    return XDP_PASS;
  */

  int_offset += (int)sizeof(struct int_header);

  ret = bpf_map_update_elem(&map_int_header, &rpc_id, int_header, BPF_ANY);

  //bpf_custom_printk("Protocolo Ethernet: %d\n", bpf_ntohs(eth->h_proto));
  //bpf_custom_printk("Qtd INT Header: %d\n", be32toh(int_header->qtd_traces));
  //bpf_custom_printk("ret update map_int_header  %d\n", ret);

  struct int_trace *int_trace1;
  struct int_trace int_trace1_map;
  struct map_key map_key;

  int_trace1 = (struct int_trace *)(int_header + 1);

  #pragma clang loop unroll (full)
  for (int i = 0 ; i < MAX_HOPS ; i++) {
    if(i < be32toh(int_header->qtd_traces)) {

      int_offset += sizeof(struct int_trace);

      //if(i==0)
        //int_trace1 = (struct int_trace *)(int_header + 1);
      //else
        //int_trace1 = (struct int_trace *) (int_trace1 + 1);

      if((int_trace1 + 1) > data_end)
        return XDP_PASS;

      __builtin_memcpy(&int_trace1_map, int_trace1, sizeof(struct int_trace));

      map_key.rpc_id = rpc_id;
      map_key.seq = i;
      ret = bpf_map_update_elem(&map_int_trace, &map_key, &int_trace1_map, BPF_ANY);
      bpf_custom_printk("ID INT swid %d: %lu ret map: %d \n", i, be32toh(int_trace1->swid), ret);

      int_trace1 = (struct int_trace *) (int_trace1 + 1);

    } else {
      break;
    }
  }



  /**
  *       Remove os dados INT do pacote
  **/

  // Faz uma copia do cabecalho Ethernet
  struct ethhdr eth_cpy;
  __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

  //ajusta o tamanho do pacote (inicio)
  ret = bpf_xdp_adjust_head(ctx, int_offset);
  bpf_custom_printk("ret bpf_xdp_adjust_head : %d\n", ret);

  //atualiza ponteiro para inicio e fim do pacote
  data_end = (void *)(long) ctx->data_end;
  data = (void *)(long) ctx->data;

  eth = data;
  if ((eth + 1) > data_end)
    return XDP_PASS;

  /* Copia de volta o cabeçalho Ethernet e atualiza o tipo do protocolo */
  __builtin_memcpy(eth, &eth_cpy, sizeof(eth_cpy));
  eth->h_proto = bpf_htons(TYPE_IPV4);


  /**
  *       Armazena MAP com os dados do server
  **/
  struct int_host int_host;
  memset(&int_host, 0, sizeof(int_host));
  int_host.tx_reqs = 1;
  int_host.time_reqs = ts;

  ret = bpf_map_update_elem(&map_int_host, &rpc_id, &int_host, BPF_ANY);
  bpf_custom_printk("ret map_int_host : %d\n", ret);

  __u64 end_time = bpf_ktime_get_ns();
  __u64 time_diff = (end_time - start_time);

  bpf_custom_printk("\n XDP_FIM rpc->id; %lu; %llu; %llu; \n", rpc_id, start_time, end_time);
  bpf_custom_printk("\n XDP_TIME rpc->id; %lu; %llu; \n", rpc_id, time_diff);
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
