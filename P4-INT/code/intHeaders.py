
from scapy.all import *
import sys, os

TYPE_IPV4       = 0x800
TYPE_INT_HEADER = 0x1212;
TYPE_INT_TRACE  = 0x1213;
TYPE_INT_HOST   = 0x1214;
TYPE_IPV4_2     = 0x1215;
TYPE_RPC        = 0xFD; #0x1215

COLLECT_SIZE    = 3;

class int_header(Packet):
    fields_desc = [ BitField("qtd_traces", 0, 32)]

class int_trace(Packet):
    if COLLECT_SIZE == 1:
        fields_desc = [ BitField("swid", 0, 32),
                        BitField("enq_qdepth", 0, 19),
                        BitField("padding", 0, 5),
                        BitField("next_proto", 0, 16)]
    elif COLLECT_SIZE == 2:
        fields_desc = [ BitField("swid", 0, 32),
                        BitField("ingress_port", 0, 9),
                        BitField("egress_port", 0, 9),
                        BitField("enq_timestamp", 0, 32),
                        BitField("enq_qdepth", 0, 19),
                        BitField("deq_timedelta", 0, 32),
                        BitField("deq_qdepth", 0, 19),
                        BitField("ingress_timestamp", 0, 48),
                        BitField("egress_timestamp", 0, 48),
                        BitField("int_field_1", 0, 24),
                        BitField("next_proto", 0, 16)]
    elif COLLECT_SIZE == 3:
        fields_desc = [ BitField("swid", 0, 32),
                        BitField("ingress_port", 0, 9),
                        BitField("egress_port", 0, 9),
                        BitField("enq_timestamp", 0, 32),
                        BitField("enq_qdepth", 0, 19),
                        BitField("deq_timedelta", 0, 32),
                        BitField("deq_qdepth", 0, 19),
                        BitField("ingress_timestamp", 0, 48),
                        BitField("egress_timestamp", 0, 48),
                        BitField("int_field_1", 0, 64),
                        BitField("int_field_2", 0, 64),
                        BitField("int_field_3", 0, 64),
                        BitField("int_field_4", 0, 64),
                        BitField("int_field_5", 0, 48),
                        BitField("int_field_6", 0, 8),
                        BitField("next_proto", 0, 16)]
    else:
        fields_desc = [ BitField("swid", 0, 8),
                        BitField("ingress_port", 0, 9),
                        BitField("egress_port", 0, 9),
                        BitField("enq_timestamp", 0, 32),
                        BitField("enq_qdepth", 0, 2),
                        BitField("deq_timedelta", 0, 32),
                        BitField("deq_qdepth", 0, 2),
                        BitField("int_field_1", 0, 2),
                        BitField("int_field_2", 0, 48),
                        BitField("int_field_3", 0, 64),
                        BitField("int_field_4", 0, 64),
                        BitField("int_field_5", 0, 48),
                        BitField("int_field_6", 0, 8),
                        BitField("next_proto", 0, 16)]

class int_host(Packet):
    fields_desc = [ BitField("tx_reqs", 0, 64),
                    BitField("time_reqs", 0, 64),
                    BitField("next_proto", 0, 16)
                    ]

class RPC(Packet):
    fields_desc = [ BitField("id", 0, 32)]

bind_layers(Ether, int_header, type=TYPE_INT_HEADER)
bind_layers(Ether, IP, type=TYPE_IPV4_2)
bind_layers(int_header, IP, qtd_traces=0)
bind_layers(int_header, int_trace)
bind_layers(int_trace, int_trace, next_proto=TYPE_INT_TRACE)
bind_layers(int_trace, int_host, next_proto=TYPE_INT_HOST)
bind_layers(int_trace, IP, next_proto=TYPE_IPV4)
bind_layers(int_host, int_trace, next_proto=TYPE_INT_TRACE)
bind_layers(int_host, IP, next_proto=TYPE_IPV4)
bind_layers(UDP,RPC)
