#include <stdint.h>

#define TYPE_INT_HEADER 4626 //0x1212
#define TYPE_INT_HOST 4628  //0x1214;
#define TYPE_IPV4 2048      //0x800;
#define TYPE_RPC 4629     //0x1215;
#define MAX_HOPS 20
#define SIZE_INT_HEADER 4
#define TYPE_UDP 17
#define TYPE_TCP 6

#define bpf_custom_printk(fmt, ...)                     \
        ({                                              \
            char ____fmt[] = fmt;                       \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                    ##__VA_ARGS__);                     \
        })

struct rpc {
    __u32 id;
};

struct int_header {
    __u32 qtd_traces;
};

#if COLLECT_SIZE == 1
    #define SIZE_INT_TRACE 9
    struct int_trace {
    		__u32 swid;
        __u16 enq_qdepth;
        __u8 padding;
        __u16 next_proto;
    } __attribute__((packed));  //72 bits  9-Bytes
#else
    #if COLLECT_SIZE == 2
        #define SIZE_INT_TRACE 36
        struct int_trace {
            __u32 swid;
            __u8 ingress_port;
            __u8 egress_port;
            __u32 enq_timestamp;
            __u16 enq_qdepth;
            __u32 deq_timedelta;
            __u16 deq_qdepth;
            __u32 ingress_timestamp;
            __u16 ingress_timestamp1;
            __u32 egress_timestamp;
            __u16 egress_timestamp1;
            __u16 int_field_1;
            __u16 padding1;
            __u16 next_proto;
        } __attribute__((packed));  //288 bits  36-Bytes
    #else
        #if COLLECT_SIZE == 3
            #define SIZE_INT_TRACE 72
            struct int_trace {
                __u32 swid;
                __u8 ingress_port;
                __u8 egress_port;
                __u32 enq_timestamp;
                __u16 enq_qdepth;
                __u32 deq_timedelta;
                __u16 deq_qdepth;
                __u32 ingress_timestamp;
                __u16 ingress_timestamp1;
                __u32 egress_timestamp;
                __u16 egress_timestamp1;
                __u8 padding1;
                __u64 int_field_1;
                __u64 int_field_2;
                __u64 int_field_3;
                __u64 int_field_4;
                __u32 int_field_51;
                __u16 int_field_52;
                __u8  int_field_6;
                __u16 next_proto;
            } __attribute__((packed));  //576 bits  72-Bytes
        #else
            #define SIZE_INT_TRACE 43
            struct int_trace {
                __u8  swid;
                __u64  int_field_1;
                __u64 int_field_2;
                __u64 int_field_3;
                __u64 int_field_4;
                __u64 int_field_5;
                __u16 next_proto;
            } __attribute__((packed));  //344 bits  43-Bytes
        #endif
    #endif
#endif

struct map_key {
    __u32 rpc_id;
    __u32 seq;
};

struct int_host {
  __u64 tx_reqs;
  __u64 time_reqs;
  __u16 next_proto;
} __attribute__((packed));//18 Bytes

struct tx_req {
    __u64 ts_init; //in nanoseconds
    __u64 count;
};

struct bpf_elf_map SEC("maps") map_tx_req = {
  .type = BPF_MAP_TYPE_HASH,
  .size_key = sizeof(int),
  .size_value = sizeof(struct tx_req),
  .max_elem = 1,
  .pinning = 2, // PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") map_int_host = {
  .type = BPF_MAP_TYPE_HASH,
  .size_key = sizeof(int),
  .size_value = sizeof(struct int_host),
  .max_elem = 512 * 1024,
  .pinning = 2, // PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") map_int_trace = {
  .type = BPF_MAP_TYPE_HASH,
  .size_key = sizeof(struct map_key),
  .size_value = sizeof(struct int_trace),
  .max_elem = 512 * 1024, //131072,
  .pinning = 2, // PIN_GLOBAL_NS
};

struct bpf_elf_map SEC("maps") map_int_header = {
  .type = BPF_MAP_TYPE_HASH,
  .size_key = sizeof(int),
  .size_value = sizeof(struct int_header),
  .max_elem = 512 * 1024,
  .pinning = 2, // PIN_GLOBAL_NS
};
