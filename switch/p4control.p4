/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#include <core.p4>
#include <tna.p4>

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

//tags data types
typedef bit<8> tag_id_t;

typedef bit<8> tag_label_t;
// typedef bit<256> tag_label_t;

typedef bit<4> dec_t;
typedef bit<4> bf_index_t;
typedef bit<1> bf_out_t;
typedef bit<16> conn_index_t;

#define  NUM_CELLS 86
#define  CONN_CELLS 210000

#define  DIGEST_REC 0
#define  DIGEST_ADD_CONN 1
// #define  DIGEST_ADD 2
// #define  DIGEST_ADD_MISSING_TAG 3

#define  BF_KEY1 32
#define  BF_KEY2 56
#define  BF_KEY3 210

#define NOTAG 0
#define DROP 1
// #define FWD 2
#define MODIFYTTL 2
#define REC 15



typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const DigestType_t MY_DIGEST=1;

const bit<16> EVIL_BIT = 0x8000;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags;
    // bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
    // bit<96> options; 
}

header icmp_h {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<16> id;
    bit<16> seq_no;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}



header flowtag_h {
    tag_label_t tag_label;
}

header flowtag_id_h {
    tag_id_t tag_id;
}

// header timestamp_h {
//     bit<64> ingress_time;
//     bit<64> egress_time;
// }

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    icmp_h icmp;
    udp_h udp;
    tcp_h tcp;
    flowtag_h flowtag;
    flowtag_id_h flowtag_id;
    // timestamp_h timestamp;
}

struct digest_t {
    ipv4_addr_t dst_addr;
    ipv4_addr_t src_addr;
    bit<16> dst_port;
    bit<16> src_port;
    bit<2> digest_op;
    tag_label_t tag_label;
    dec_t decision;
}

struct metadata_t {
    // bridge_h bridge_hdr;
    
    ipv4_addr_t dst_addr;
    ipv4_addr_t src_addr;
    bit<16> dst_port;
    bit<16> src_port;
    // tag_id_t tag_id;

    tag_label_t tag_label;
    tag_label_t declassify_label;
    tag_label_t dst_tag_label;

    bit<2> digest_op;

    dec_t decision;
    dec_t decision2;

    bit<1> checksum_upd_ipv4;
    
    bit<16> priority_2;
    bit<16> priority_3;
    bit<16> priority_4;
    bit<16> priority_5;

    // dec_t priority_1_dec;
    dec_t priority_2_dec;
    dec_t priority_3_dec;
    dec_t priority_4_dec;
    dec_t priority_5_dec;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser TofinoIngressParser(
            packet_in pkt,
            out ingress_intrinsic_metadata_t ig_intr_md) {
        state start {
            pkt.extract(ig_intr_md);
            transition select(ig_intr_md.resubmit_flag) {
                1 : parse_resubmit;
                0 : parse_port_metadata;
            }
        }

        state parse_resubmit {
            // Parse resubmitted packet here.
            transition reject;
        }

        state parse_port_metadata {
            pkt.advance(PORT_METADATA_SIZE);
            transition accept;
        }
}
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_UDP  : parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select (hdr.ipv4.flags[15:15]) {
            1 : parse_tag;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select (hdr.ipv4.flags[15:15]) {
            1 : parse_tag;
            default : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition select (hdr.ipv4.flags[15:15]) {
            1 : parse_tag;
            default : accept;
        }
    }

    state parse_tag {
        pkt.extract(hdr.flowtag);
        pkt.extract(hdr.flowtag_id);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    // bit<2> diff;
    tag_label_t check_label;

    bit<16> cur_priority = 0xFFFF;
    bit<16> priority2 = 0xFFFF;
    bit<16> priority3 = 0xFFFF;
    bit<16> priority4 = 0xFFFF;

    dec_t priority_2_dec = 0;
    dec_t priority_3_dec = 0;
    dec_t priority_4_dec = 0;
    dec_t priority_5_dec = 0;
    

    action route(bit<9> dst_port) {
        ig_intr_tm_md.ucast_egress_port = dst_port;
        ig_dprsr_md.drop_ctl = 0x0;
    }

    action miss() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table table_forward {
        key = {
            hdr.ipv4.dst_addr : exact;
        }

        actions = {
            route;
            miss;
        }

        const default_action = miss;
        size = 16;
    }

    //Connection table
    Register<bit<8>, conn_index_t> (size=CONN_CELLS, initial_value=0) cache_conn;
    //the first inout argument is the value of the Register entry being read and
    //updated, while the second optional out argument is the value that will be returned by
    //the execute method
    RegisterAction<bit<8>, conn_index_t, bit<8>>(cache_conn) conn_check = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<8>, conn_index_t, bit<8>>(cache_conn) conn_add = {
        void apply(inout bit<8> value, out bit<8> read_value) {
            read_value = (bit<8>) ig_md.decision;
            value = (bit<8>) ig_md.decision;
        }
    };

    Hash<conn_index_t>(HashAlgorithm_t.CRC16) conn_hash;



    action prepare_digest(bit<2> digest_op){
        ig_dprsr_md.digest_type = MY_DIGEST;
        ig_md.dst_addr = hdr.ipv4.dst_addr;
        ig_md.src_addr = hdr.ipv4.src_addr;
        ig_md.src_port = hdr.tcp.src_port;
        ig_md.dst_port = hdr.tcp.dst_port;
        // ig_md.tag_id = hdr.flowtag.tag_id;
        ig_md.digest_op = digest_op;
        ig_md.tag_label = hdr.flowtag.tag_label;
    }

    action enforce_dec(dec_t decision){
        ig_md.decision = decision;
    }

    action get_dst_label(tag_label_t dst_label){
        ig_md.dst_tag_label = dst_label;
    }

    table table_dst_tag_label {
        key = {
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            get_dst_label;
        }
        size = 32;
    }

    action reroute(bit<9> egress_port) {
		ig_intr_tm_md.ucast_egress_port = egress_port;
	}

    action modify(){
        hdr.ipv4.ttl = 55;
        ig_md.checksum_upd_ipv4 = 1;
    }


    table table_dec {
        key = {
            ig_md.decision: exact;
        }
        
        actions = {
            reroute;
            miss;
            modify;
            // alert; //send with digest to control plane
            NoAction;
        }

        const default_action = NoAction;
        size = 16;
    }

    

    //maintain connection decision in a m/a table (also is maintained in register)
    table table_conn {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            hdr.tcp.src_port: exact;
            hdr.tcp.dst_port: exact;
        }
        actions = {
            enforce_dec;
        }
        size = CONN_CELLS;
        // size = 1024;
    }

    // action table_action(bit<16> priority, dec_t decision) {
    //     // hdr.ipv4.ttl = 110;
    //     ig_md.bridge_hdr.priority_1 = priority;
    //     // ig_md.bridge_hdr.decision = decision;
    //     cur_priority = min(priority, cur_priority);
    // }

    action table_action2(bit<16> priority, dec_t decision, tag_label_t declassify_label) {
        // hdr.ipv4.ttl = 120;
        priority2 = priority;
        hdr.flowtag.tag_label = hdr.flowtag.tag_label & declassify_label;
        priority_2_dec = decision;
        cur_priority = min(priority, cur_priority);
    }

    action table_action3(bit<16> priority, dec_t decision) {
        // hdr.ipv4.ttl = 130;
        priority3 = priority;
        priority_3_dec = decision;
        cur_priority = min(priority, cur_priority);
    }

    action table_action4(bit<16> priority, dec_t decision) {
        // hdr.ipv4.ttl = 140;
        priority4 = priority;
        priority_4_dec = decision;
        cur_priority = min(priority, cur_priority);
    }

    action table_action5(bit<16> priority, dec_t decision) {
        // hdr.ipv4.ttl = 150;
        // ig_md.priority_5 = priority;
        priority_5_dec = decision;
        cur_priority = min(priority, cur_priority);
    }


    //check label && dst
    // table t_table_action { 
    //     key = {
    //         // hdr.ipv4.src_addr : exact;
    //         hdr.ipv4.dst_addr : exact;
    //         hdr.flowtag.tag_label : ternary;
    //     }
    //     actions = {
    //         table_action;
    //     }
    //     size = 10000;
    // }

    //check src && dst
    table t_table_action2 { 
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            table_action2;
        }
        size = 1000;
    }

    //check label && dst_label
    table t_table_action3 { 
        key = {
            hdr.flowtag.tag_label : ternary;
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            table_action3;
        }
        size = 1000;
    }

    //check tag_id && dst
    table t_table_action4 { 
        key = {
            hdr.ipv4.dst_addr : exact;
            hdr.flowtag_id.tag_id : exact;
        }
        actions = {
            table_action4;
        }
        size = 1000;
    }

    //check tag_id && dst_lable
    table t_table_action5 { 
        key = {
            hdr.flowtag_id.tag_id : exact;
            ig_md.dst_tag_label : exact;
        }
        actions = {
            table_action5;
        }
        size = 1000;
    }
    

    apply {
        //merge dst label with current lable
        if(hdr.flowtag.isValid()){
            table_dst_tag_label.apply();
            hdr.flowtag.tag_label = hdr.flowtag.tag_label | ig_md.dst_tag_label;
        }

        // @stage(1){
        // t_table_action.apply();
        // }

        // @stage(3){
        //Declassify and endorsement
        t_table_action2.apply();
        // }

        // @stage(4){
        t_table_action3.apply();
        // }

        // @stage(4){
        t_table_action4.apply();
        // }

        // @stage(5){
        t_table_action5.apply();
        // }
        
        if(hdr.ipv4.flags[15:15] == (bit<1>)1){
            if(cur_priority == priority2){
                ig_md.decision = priority_2_dec;
            } else if(cur_priority == priority3){
                ig_md.decision = priority_3_dec;
            } else if(cur_priority == priority4){
                ig_md.decision = priority_4_dec;
            } else{
                ig_md.decision = priority_5_dec;
            }
            ig_md.decision2 = ig_md.decision;
            conn_add.execute(conn_hash.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}));
            prepare_digest(DIGEST_ADD_CONN);
        }
        //else if the packet is following a tagged packet
        else{
            ig_md.decision2 = (bit<4>)conn_check.execute(conn_hash.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}));
            table_conn.apply();
        }

        ig_md.decision = ig_md.decision2;
        table_forward.apply();
        table_dec.apply();

        // No need for egress processing, skip it and use empty controls for egress.
        ig_intr_tm_md.bypass_egress = 1w1;
    }
}
// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    
    Digest<digest_t>() my_digest;
    Checksum() ipv4_checksum;

    apply {
        if (ig_dprsr_md.digest_type == MY_DIGEST) {
            my_digest.pack({ig_md.dst_addr, ig_md.src_addr, ig_md.dst_port, ig_md.src_port, ig_md.digest_op, ig_md.tag_label, ig_md.decision});
        }

        if (ig_md.checksum_upd_ipv4==1) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.total_len,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.src_addr,
                 hdr.ipv4.dst_addr});
        }
        // pkt.emit(ig_md.bridge_hdr);
        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------
// struct my_metadata_t{
    
// }
parser SwitchEgressParser(packet_in packet, out header_t hdr, out metadata_t eg_md, out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
		packet.extract(eg_intr_md);
        // packet.extract(eg_md.bridge_hdr);
		// packet.extract(meta.bridged_metadata);
		packet.extract(hdr.ethernet);
		packet.extract(hdr.ipv4);
        // packet.extract(hdr.tcp);
        // packet.extract(hdr.flowtag);
		// packet.extract(hdr.timestamp);
		transition accept;
	}

}


// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
    inout header_t hdr,
	inout metadata_t eg_md,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_parser_md,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {


	apply{

	}

}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(packet_out packet, inout header_t hdr, in metadata_t eg_md, in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
      packet.emit(hdr);  
    }

}


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;