/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 20
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_RECIRC 4
#define PKT_INSTANCE_TYPE_RESUBMIT 6
#define TYPE_UDP 17
#define TYPE_TCP 6

#ifndef FREQ
#define FREQ 0
#endif

const bit<16> TYPE_IPV4       = 0x800;
const bit<16> TYPE_IPV4_2     = 0x1215;
const bit<16> TYPE_INT_HEADER = 0x1212;
const bit<16> TYPE_INT_TRACE  = 0x1213;
const bit<16> TYPE_INT_HOST   = 0x1214;
const bit<8>  TYPE_RPC        = 0xFD; //0x1215

#define SIZE_INT_HEADER 4
#define SIZE_INT_HOST 18
#define SIZE_ETHERNET 14
#define SIZE_IPv4 20
#define SIZE_RPC 4
#define SIZE_UDP 8
#define SIZE_NORMAL_PKT SIZE_ETHERNET + SIZE_IPv4 + SIZE_UDP


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
} //112 bits, 14 bytes

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
} //160 bits, 20 Bytes

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header rpc_t {
    bit<32> id;
} //6 Bytes

header int_header_t {
    bit<32> q_traces;
}

#if COLLECT_SIZE == 1
  #define SIZE_INT_TRACE 9
#else
  #if COLLECT_SIZE == 2
    #define SIZE_INT_TRACE 36
  #else
    #if COLLECT_SIZE == 3
      #define SIZE_INT_TRACE 72
    #else //alto discretizado
      #define SIZE_INT_TRACE 43
    #endif
  #endif
#endif

#if COLLECT_SIZE == 1
  header int_trace_t {
      bit<32>  swid;
      bit<19>  enq_qdepth;
      bit<5>   padding;
      bit<16>  next_proto;
      //72 bits (9 Bytes)
  }
#else
  #if COLLECT_SIZE == 2
    header int_trace_t {
      bit<32> swid;
      bit<9>  ingress_port;
      bit<9>  egress_port;
      bit<32> enq_timestamp;
      bit<19> enq_qdepth;
      bit<32> deq_timedelta;
      bit<19> deq_qdepth;
      bit<48> ingress_timestamp;
      bit<48> egress_timestamp;
      bit<24> int_field_1;
      bit<16>  next_proto;
      //288 bits (36 Bytes)
    }
  #else
    #if COLLECT_SIZE == 3
      header int_trace_t {
        bit<32> swid;
        bit<9>  ingress_port;
        bit<9>  egress_port;
        bit<32> enq_timestamp;
        bit<19> enq_qdepth;
        bit<32> deq_timedelta;
        bit<19> deq_qdepth;
        bit<48> ingress_timestamp;
        bit<48> egress_timestamp;
        bit<64> int_field_1;
        bit<64> int_field_2;
        bit<64> int_field_3;
        bit<64> int_field_4;
        bit<48> int_field_5;
        bit<8>  int_field_6;
        bit<16>  next_proto;
        //576 bits (72 Bytes)
      }
    #else
      //#if COLLECT_SIZE == 4 //Otimizado discretizado
        header int_trace_t {
          bit<8>  swid; //bit<32>  swid;
          bit<9>  ingress_port;
          bit<9>  egress_port;
          bit<32> enq_timestamp;
          bit<2>  enq_qdepth; //bit<19> enq_qdepth;
          bit<32> deq_timedelta;
          bit<2>  deq_qdepth; //bit<19> deq_qdepth;
          //bit<48> ingress_timestamp;
          //bit<48> egress_timestamp;
          bit<2> int_field_1;  //packet_length
          bit<48> int_field_2;  //egress_timestamp-ingress_timestamp
          bit<64> int_field_3;
          bit<64> int_field_4;
          bit<48> int_field_5;  //last_INT_timestamp;
          bit<8>  int_field_6;
          bit<16>  next_proto;
          //344 bits (43 Bytes) economia de 29 bytes
        }
      //#endif
    #endif
  #endif
#endif


header int_host_t {
    bit<64> tx_reqs;
    bit<64> time_reqs;
    bit<16>  next_proto;
} //144 bits (18 Bytes)

struct metadata {
    bit<32> q_traces;
    bit<1>  isEndHost;
    bit<32> packet_size;
    @field_list(1)
    bit<9> ingress_port;
    @field_list(1)
    bit<9>  egress_port;
    @field_list(1)
    bit <48> ingress_timestamp;
    @field_list(1)
    bit<19> deq_qdepth;
    @field_list(1)
    bit<32> enq_timestamp;
    @field_list(1)
    bit<19> enq_qdepth;
    @field_list(1)
    bit<32> deq_timedelta;
    @field_list(1)
    bit<48> last_INT_timestamp;
    @field_list(1)
    bit<1> add_INT;
    @field_list(1)
    bit<48> tot_packets;
}

struct headers {
    ethernet_t                ethernet;
    ipv4_t                    ipv4;
    rpc_t                     rpc;
    int_header_t              int_header;
    int_trace_t[MAX_HOPS]     int_trace;
    int_host_t                int_host;
    udp_t                     udp;
}

register<bit<48>>(960) last_INT_timestamp;
register<bit<48>>(960) tot_packets;
