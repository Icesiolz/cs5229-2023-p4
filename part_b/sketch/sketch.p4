/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;
const bit<8> TYPE_ICMP = 0x01;
const bit<16> HASH_MAX = 65535;

#define SKETCH_ROW_LENGTH 65536
#define SKETCH_CELL_BIT_WIDTH 32

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
}

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
}

header icmp_t {
    /* TODO: your code here */
    bit<8>    type;
    bit<8>    code;
    bit<16>   hdrChecksum;
}

header tcp_t {
    /* TODO: your code here */
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<32>   seqNo;
    bit<32>   ackNo;
    bit<4>    offset;
    bit<3>    reserved;
    bit<9>    ctrlFlag;
    bit<16>   length;
    bit<16>   hdrChecksum;
    bit<16>   urgentPointer;
}

header udp_t {
    /* TODO: your code here */
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   length;
    bit<16>   hdrChecksum;
}

struct metadata {
    /* TODO: your code here */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    tcp_t        tcp;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        /* TODO: your code here */
        /* Hint: implement your parser */
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
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
    
    bit<32> hh_threshold = 0;
    bit<32> drop_threshold = 0;
    
    /* sketch data structure */
    /* Note: you may modify this structure as you wish */
    register<bit<SKETCH_CELL_BIT_WIDTH>> (SKETCH_ROW_LENGTH)  sketch_row0;
    register<bit<SKETCH_CELL_BIT_WIDTH>> (SKETCH_ROW_LENGTH)  sketch_row1;
    register<bit<SKETCH_CELL_BIT_WIDTH>> (SKETCH_ROW_LENGTH)  sketch_row2;
    register<bit<SKETCH_CELL_BIT_WIDTH>> (SKETCH_ROW_LENGTH)  sketch_row3;  

    /* TODO: your code here, if needed ;) */
    // ...

    action mirror_heavy_flow() {
        clone(CloneType.I2E, 0);    // mirror detected heavy flows to ports under session 0.
    }
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action get_thresholds_action(bit<32> hh_threshold_param, bit<32> drop_threshold_param) {
        hh_threshold = hh_threshold_param;
        drop_threshold = drop_threshold_param;
    }

    table get_thresholds {
        key = {}
        actions = {
            NoAction;
            get_thresholds_action;
        }
        default_action = NoAction();
    }

    action ipv4_forward_action(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward_action;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            /* TODO: your code here */
            get_thresholds.apply();
            /* Hint 1: update the sketch and get the latest estimation */
            
            bit<32> count = 0;
            bit<16> srcPort = 0;
            bit<16> dstPort = 0;
            ip4Addr_t srcAddr = hdr.ipv4.srcAddr;
            ip4Addr_t dstAddr = hdr.ipv4.dstAddr;
            bit<8> protocol = hdr.ipv4.protocol;

            if (protocol == TYPE_TCP) {
                srcPort = hdr.tcp.srcPort;
                dstPort = hdr.tcp.dstPort;
            }

            if (protocol == TYPE_UDP) {
                srcPort = hdr.udp.srcPort;
                dstPort = hdr.udp.dstPort;
            }

            /* Count-Min sketch */
            bit<32> row0_idx;
            bit<32> row0_count;
            bit<32> row1_idx;
            bit<32> row1_count;
            bit<32> row2_idx;
            bit<32> row2_count;
            bit<32> row3_idx;
            bit<32> row3_count;

            hash(row0_idx, HashAlgorithm.crc32, (bit<16>) 0, {srcAddr, dstAddr, srcPort, dstPort, protocol}, HASH_MAX);
            sketch_row0.read(row0_count, row0_idx);
            row0_count = row0_count + 1;
            sketch_row0.write(row0_idx, row0_count);

            hash(row1_idx, HashAlgorithm.crc16, (bit<16>) 0, {srcAddr, dstAddr, srcPort, dstPort, protocol}, HASH_MAX);
            sketch_row1.read(row1_count, row1_idx);
            row1_count = row1_count + 1;
            sketch_row1.write(row1_idx, row1_count);

            hash(row2_idx, HashAlgorithm.csum16, (bit<16>) 0, {srcAddr, dstAddr, srcPort, dstPort, protocol}, HASH_MAX);
            sketch_row2.read(row2_count, row2_idx);
            row2_count = row2_count + 1;
            sketch_row2.write(row2_idx, row2_count);

            hash(row3_idx, HashAlgorithm.xor16, (bit<16>) 0, {srcAddr, dstAddr, srcPort, dstPort, protocol}, HASH_MAX);
            sketch_row3.read(row3_count, row3_idx);
            row3_count = row3_count + 1;
            sketch_row3.write(row3_idx, row3_count);

            count = row0_count;
            if (row1_count < count) {
                count = row1_count;
            }
            if (row2_count < count) {
                count = row2_count;
            }
            if (row3_count < count) {
                count = row3_count;
            }

            /* Hint 2: compare the estimation with the hh_threshold */
            /* Hint 3: to report HH flow, call mirror_heavy_flow() */
            /* Hint 4: how to ensure no duplicate HH reports to collector? */
            if (count == hh_threshold + 1) {
                mirror_heavy_flow();
            }

            /* Hint 5: check drop_threshold, and drop if it is a potential DNS amplification attack */
            if (count > drop_threshold) {
                drop();
                return;
            }

            ipv4_forward.apply();
        } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: your code here */
        packet.emit(hdr);
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
