/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "INT_headers.h"

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_INT_HEADER: parse_int_header;
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV4_2: parse_ipv4;
            default: accept;
        }
    }

    state parse_int_header {
        packet.extract(hdr.int_header);
        meta.q_traces = hdr.int_header.q_traces;
        transition select(hdr.int_header.q_traces) {
            0: parse_ipv4;
            default: parse_int_trace;
        }
    }

    state parse_int_trace {
        packet.extract(hdr.int_trace.next);
        transition select(hdr.int_trace.last.next_proto) {
            TYPE_INT_TRACE: parse_int_trace;
            TYPE_INT_HOST: parse_int_host;
            TYPE_IPV4: parse_ipv4;
        }
    }

    state parse_int_host {
        packet.extract(hdr.int_host);
        meta.q_traces = meta.q_traces + 1;
        transition select(hdr.int_host.next_proto) {
            TYPE_INT_TRACE: parse_int_trace;
            TYPE_IPV4: parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            //TYPE_RPC: parse_rpc;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_rpc;
        /*transition select(hdr.eth) {
            TYPE_RPC: parse_rpc;
            default: accept;
        } */
    }

    state parse_rpc {
      packet.extract(hdr.rpc);
      transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<1> isEndHost) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        meta.isEndHost = isEndHost;
        meta.egress_port = port;
        meta.ingress_port = standard_metadata.ingress_port;
        meta.ingress_timestamp = (bit <48>) standard_metadata.ingress_global_timestamp;
        meta.deq_qdepth   = standard_metadata.deq_qdepth;

        meta.enq_timestamp   = standard_metadata.enq_timestamp;
        meta.enq_qdepth   = standard_metadata.enq_qdepth;
        meta.deq_timedelta   = standard_metadata.deq_timedelta;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {

            ipv4_lpm.apply();

            bit<48> T=FREQ;
            last_INT_timestamp.read(meta.last_INT_timestamp, (bit<32>)meta.egress_port);
            tot_packets.read(meta.tot_packets, (bit<32>)meta.egress_port);

            //check if INT data should be added
            if((T == 0 || standard_metadata.ingress_global_timestamp - meta.last_INT_timestamp >= T && T > 0) && hdr.rpc.isValid() && meta.q_traces < MAX_HOPS) {
                meta.add_INT = 1;
                last_INT_timestamp.write((bit<32>)meta.egress_port, standard_metadata.ingress_global_timestamp);
                tot_packets.write((bit<32>)meta.egress_port, 0);
            } else {
                meta.add_INT = 0;
                last_INT_timestamp.write((bit<32>)meta.egress_port, standard_metadata.ingress_global_timestamp);  //TODO
            }

            if( (hdr.int_header.isValid() || meta.add_INT == 1) && meta.isEndHost == 1) {
                clone_preserving_field_list(CloneType.I2E, 500, 1);
            }

            meta.tot_packets = meta.tot_packets + 1;
            tot_packets.write((bit<32>)meta.egress_port, meta.tot_packets);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action add_int_header() {
        hdr.int_header.setValid();
        hdr.int_header.q_traces = 0;
        hdr.ethernet.etherType = TYPE_INT_HEADER;
    }

    action add_int_trace(bit<32> swid) {
        hdr.int_trace.push_front(1);
        hdr.int_trace[0].setValid();

        #if COLLECT_SIZE == 1
            hdr.int_trace[0].swid           = swid;
            hdr.int_trace[0].enq_qdepth     = meta.enq_qdepth;
            hdr.int_trace[0].padding        = 0;
            hdr.int_trace[0].next_proto     = TYPE_INT_TRACE;

        #else
          #if COLLECT_SIZE == 2
                hdr.int_trace[0].swid           = swid;
                hdr.int_trace[0].ingress_port   = meta.ingress_port;
                hdr.int_trace[0].egress_port    = meta.egress_port;
                hdr.int_trace[0].enq_timestamp  = meta.enq_timestamp;
                hdr.int_trace[0].enq_qdepth     = meta.enq_qdepth;
                hdr.int_trace[0].deq_timedelta  = meta.deq_timedelta;
                hdr.int_trace[0].deq_qdepth     = meta.deq_qdepth;
                hdr.int_trace[0].ingress_timestamp = (bit <48>) meta.ingress_timestamp;
                hdr.int_trace[0].egress_timestamp = (bit <48>) meta.ingress_timestamp;
                hdr.int_trace[0].int_field_1      = 0;
                hdr.int_trace[0].next_proto     = TYPE_INT_TRACE;

          #else
            #if COLLECT_SIZE == 3
                hdr.int_trace[0].swid           = swid;
                hdr.int_trace[0].ingress_port   = meta.ingress_port;
                hdr.int_trace[0].egress_port    = meta.egress_port; //standard_metadata.egress_port;
                hdr.int_trace[0].enq_timestamp  = meta.enq_timestamp;
                hdr.int_trace[0].enq_qdepth     = meta.enq_qdepth;
                hdr.int_trace[0].deq_timedelta  = meta.deq_timedelta;
                hdr.int_trace[0].deq_qdepth     = meta.deq_qdepth;
                hdr.int_trace[0].ingress_timestamp = (bit <48>) meta.ingress_timestamp;
                hdr.int_trace[0].egress_timestamp = (bit <48>) standard_metadata.egress_global_timestamp;
                hdr.int_trace[0].int_field_1    = (bit <64>) standard_metadata.packet_length;
                hdr.int_trace[0].int_field_2    = (bit <64>) (standard_metadata.egress_global_timestamp - meta.ingress_timestamp);
                hdr.int_trace[0].int_field_3    = 0;
                hdr.int_trace[0].int_field_4    = (bit <64>)meta.tot_packets;
                hdr.int_trace[0].int_field_5    = meta.last_INT_timestamp;
                hdr.int_trace[0].int_field_6    = 0;
                hdr.int_trace[0].next_proto     = TYPE_INT_TRACE;
            #else
                hdr.int_trace[0].swid           = (bit <8>) swid;
                hdr.int_trace[0].ingress_port   = meta.ingress_port;
                hdr.int_trace[0].egress_port    = meta.egress_port;
                hdr.int_trace[0].enq_timestamp  = meta.enq_timestamp;
                hdr.int_trace[0].enq_qdepth     = 1; //meta.enq_qdepth;
                hdr.int_trace[0].deq_timedelta  = meta.deq_timedelta;
                hdr.int_trace[0].deq_qdepth     = 2; //meta.deq_qdepth;
                hdr.int_trace[0].int_field_1    = 3; // standard_metadata.packet_length;
                hdr.int_trace[0].int_field_2    = 0; //standard_metadata.egress_global_timestamp - meta.ingress_timestamp;
                hdr.int_trace[0].int_field_3    = 0;
                hdr.int_trace[0].int_field_4    = 0;
                hdr.int_trace[0].int_field_5    = meta.last_INT_timestamp;
                hdr.int_trace[0].int_field_6    = 0;
                hdr.int_trace[0].next_proto     = TYPE_INT_TRACE;
            #endif
          #endif
        #endif

        hdr.int_header.q_traces = hdr.int_header.q_traces + 1;
    }

    action forward_int(macAddr_t dstAddr, ip4Addr_t ip_dstAddr) {
        //calcular o tamanho do pacote
        meta.packet_size = SIZE_NORMAL_PKT + SIZE_INT_HEADER + (SIZE_INT_TRACE * hdr.int_header.q_traces);

        if(hdr.int_host.isValid()){
          meta.packet_size = meta.packet_size + SIZE_INT_HOST;
        }

        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl         = 64;
        hdr.ipv4.dstAddr     = ip_dstAddr;

        //Remove payload
        truncate(meta.packet_size);
    }

    action int_sink() {
        hdr.int_trace.pop_front(MAX_HOPS);
        hdr.int_header.q_traces=0;

        hdr.int_header.setInvalid();

        hdr.int_host.setInvalid();
        hdr.ethernet.etherType = TYPE_IPV4; //TYPE_IPV4_2
    }

    table t_forward_int {
        actions = {
            forward_int;
            NoAction;
        }
        default_action = NoAction();
    }

    table int_trace {
        actions = {
            add_int_trace;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {

        if (hdr.ipv4.isValid()) {

            if(meta.add_INT == 1) {

              if(!hdr.int_header.isValid()) {
                  add_int_header();
              }

              int_trace.apply();

              if(hdr.int_header.isValid() && hdr.int_header.q_traces == 1) {
                hdr.int_trace[0].next_proto     = TYPE_IPV4;
              }

            }

            if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL && meta.isEndHost == 1 && hdr.int_header.isValid() ) {
                int_sink();
            } else if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {

                t_forward_int.apply();
            }

        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_trace);
        packet.emit(hdr.int_host);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.rpc);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
