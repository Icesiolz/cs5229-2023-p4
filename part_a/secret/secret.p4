/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SECRET = 0xFFFF;
const bit<32> SWITCH_IP = 0x0a0000FE;

enum bit<16> SECRET_OPT {
    DROPOFF = 0x0001,
    PICKUP  = 0x0002,
    SUCCESS = 0xFFFF,
    FAILURE = 0x0000
}

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
    /* Hint: define ICMP header */
    bit<8>    type;
    bit<8>    code;
    bit<16>   hdrChecksum;
}

header udp_t {
    /* TODO: your code here */
    /* Hint: define UDP header */
    bit<16>   srcPort;
    bit<16>   dstPort;
    bit<16>   length;
    bit<16>   hdrChecksum;
}

header secret_t {
    bit<16> opCode; 
    bit<16> mailboxNum;
    bit<32> message;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    secret_t     secret;
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
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.srcPort) {
            TYPE_SECRET: parse_secret;
            default: accept;
        }
    }

    state parse_secret {
        packet.extract(hdr.secret);
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
    
    register<bit<32>>(65536) secret_mailboxes;
    register<bit<32>>(65536) msg_checksums;

    action drop() {
        mark_to_drop(standard_metadata);
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
        default_action = drop();
    }

    apply {
        if(hdr.secret.isValid()) {
            /* TODO: your code here */
            /* Hint 1: verify if the secret message is destined to the switch */
            if (hdr.ipv4.dstAddr == SWITCH_IP && hdr.udp.dstPort == TYPE_SECRET) {
               
                bit<32> message;
                bit<32> msg_checksum;

                /* Hint 2: there are two cases to handle -- DROPOFF, PICKUP */
                if (hdr.secret.opCode == SECRET_OPT.DROPOFF) {
                    secret_mailboxes.read(message, (bit<32>)hdr.secret.mailboxNum);
                    if (message == 0) {
                        hash(msg_checksum, HashAlgorithm.crc32, (bit<32>) 0, {hdr.secret.message}, (bit<32>)2147483647);
                        secret_mailboxes.write((bit<32>)hdr.secret.mailboxNum, hdr.secret.message);
                        msg_checksums.write((bit<32>)hdr.secret.mailboxNum, msg_checksum);
                        hdr.secret.opCode = SECRET_OPT.SUCCESS;
                    } else {
                        hdr.secret.opCode = SECRET_OPT.FAILURE;
                    }
                } 
                
                if (hdr.secret.opCode == SECRET_OPT.PICKUP) {
                /* Hint 3: what happens when you PICKUP from an empty mailbox? */
                    bit<32> msg_checksum_check;
                    secret_mailboxes.read(message, (bit<32>)hdr.secret.mailboxNum);
                    msg_checksums.read(msg_checksum_check, (bit<32>)hdr.secret.mailboxNum);
                    hash(msg_checksum, HashAlgorithm.crc32, (bit<32>) 0, {message}, (bit<32>)2147483647);

                    if (message == 0 || msg_checksum != msg_checksum_check) {
                        hdr.secret.opCode = SECRET_OPT.FAILURE;
                    } else {
                        hdr.secret.message = message;
                        hdr.secret.opCode = SECRET_OPT.SUCCESS;
                /* Hint 4: remember to "sanitize" your mailbox with 0xdeadbeef after every PICKUP */
                        bit<32> empty_msg = 0xdeadbeef;
                        secret_mailboxes.write((bit<32>)hdr.secret.mailboxNum, empty_msg);
                        msg_checksums.write((bit<32>)hdr.secret.mailboxNum, (bit<32>)0);

                    }
                }

                /* Hint 5: msg_checksums are important! */

                /* Hint 6: once everything is done, swap addresses, set port and reply to sender */
                macAddr_t tmp_macAddr;
                ip4Addr_t tmp_ip4Addr;

                tmp_macAddr = hdr.ethernet.dstAddr;
                hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
                hdr.ethernet.srcAddr = tmp_macAddr;

                tmp_ip4Addr = hdr.ipv4.dstAddr;
                hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
                hdr.ipv4.srcAddr = tmp_ip4Addr;

                //standard_metadata.egress_spec = standard_metadata.ingress_port;
            } 
        }
        ipv4_forward.apply();
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
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
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
