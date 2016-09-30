#!/usr/bin/python
import socket
from struct import *
import datetime
import pcapy
import sys
import getopt
import logging
import signal
import hashlib
import protocol_dict as protocol_dict


srcips = {}


def signal_handler(signal, frame):
    try:
        sorted_srcips = sorted(srcips.items(), key=lambda t: t[1], reverse=True)
        wtf('srcip.txt', str(sorted_srcips))
    except Exception, e:
        print str(e)
    print '\nExiting...\n'
    sys.exit(0)


def wtf(fname, buff):
    try:
        fso = open(fname, 'a')
        fso.write(buff)
        fso.close()
    except Exception, e:
        print str(e)


# MAC Layer
def parsel2_metadata(packet):
    try:
        header = packet[:14]
        dest_mac, src_mac, proto = unpack('!6s6sH', header)
        return socket.ntohs(proto), format_mac_address(dest_mac), format_mac_address(src_mac)
    except Exception, e:
        logging.error(str(e))
    except KeyboardInterrupt:
        sys.exit(0)


# IP Layer
def parsel3_metadata(packet):
    try:
        iph = unpack('!BBHHHBBH4s4s', packet[:20])
        version_header_length = iph[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 0xF)*4
        ttl = iph[5]
        proto = int(iph[6])
        srcip = iph[8]
        destip = iph[9]
        return int(proto), socket.inet_ntoa(srcip), socket.inet_ntoa(destip), header_length
    except Exception, e:
        logging.error(str(e))


# Protocol
def parsel4_metadata(protonum):
    # protocol_dict = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 115: "L2TP"}
    try:
        return protocol_dict.protocol_def[str(protonum)]
    except Exception, e:
        return protonum


# Port / Session
def parsel5_metadata(packet, protonum):
    # ICMP
    if protonum == 1:
        icmp_type, code, checksum = unpack('!BBH', packet[:4])
        return icmp_type, code, checksum
    # TCP
    if protonum == 6:
        sPort, dPort = unpack('!HH', packet[:4])
        return sPort, dPort
    # UDP
    if protonum == 17:
        sPort, dPort = unpack('!HH', packet[:4])
        return sPort, dPort
    # Everything else
    else:
        return protonum


def format_mac_address(a):
    # format chunk into 00:11:22:33:44:55:66:77
    try:
        mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
        return mac.upper()
    except Exception, e:
        logging.debug(str(e))


def monitor_traffic(iface):
    try:
        pcap = pcapy.open_live(iface, 1500, 1, 0)
        i = 0
        while(1):
            (header, packet) = pcap.next()
            l1_proto, dest_mac, src_mac = parsel2_metadata(packet)
            proto_num, src_ip, dest_ip, hl = parsel3_metadata(packet[14:])
            protocol = parsel4_metadata(proto_num)
            l5 = parsel5_metadata(packet[14 + hl:], proto_num)
            nethash = hashlib.md5(src_ip+dest_ip).hexdigest()
            if (proto_num == 6) or (proto_num == 17):
                fingerprint = hashlib.md5(dest_ip+str(l5[1])).hexdigest()
                # print "SMAC:", src_mac, '->', 'DMAC:', dest_mac, 'srcIP:', src_ip, '->', 'destIP:', dest_ip, 'Protocol:', protocol, 'Layer5:', l5, 'NetHash:', nethash, 'fingerprint:', fingerprint
                wtf('nalyzer.log', str("SMAC: " + src_mac + ' -> ' + 'DMAC: ' + dest_mac + ' srcIP: ' + src_ip + ' -> ' + 'destIP: ' + dest_ip + ' Protocol: ' + str(protocol) + ' Layer5: ' + str(l5) + ' NetHash: ' + nethash + ' fingerprint: ' + fingerprint +'\n'))
                top_talker_source(src_ip)
            else:
                # print "SMAC:", src_mac, '->', 'DMAC:', dest_mac, 'srcIP:', src_ip, '->', 'destIP:', dest_ip, 'Protocol:', protocol, 'Layer5:', l5, 'NetHash:', nethash
                wtf('nalyzer.log', str("SMAC: " + src_mac + ' -> ' + 'DMAC: ' + dest_mac + ' srcIP: ' + src_ip + ' -> ' + 'destIP: ' + dest_ip + ' Protocol: ' + str(protocol) + ' Layer5: ' + str(l5) + ' NetHash: ' + nethash + '\n'))
                top_talker_source(src_ip)
    except Exception, e:
        logging.warn(str(e))
    except KeyboardInterrupt:
        sys.exit(0)


def top_talker_source(srcip):
    if srcip in srcips:
        srcips[srcip] += 1
    else:
        srcips[srcip] = 1
    # print srcip, ':', srcips[srcip]
    # print '\n', srcips


def main(argv):
    try:
        signal.signal(signal.SIGINT, signal_handler)
        ifaces = pcapy.findalldevs()
        try:
            opts, args = getopt.getopt(argv,"hi:",["iface="])
            for opt, arg in opts:
                if opt == '-h':
                    print 'Usage:', sys.argv[0], '-i <interface>'
                elif opt in ("-i", "--iface"):
                    iface = arg
                    if iface in ifaces:
                        monitor_traffic(iface)
                    else:
                        print 'Invalid capture devie !\n'
            if len(opts) == 0:
                i = 0
                print 'Available interfaces:\n'
                for iface in ifaces:
                    print i, ':', iface
                    i += 1
                iDev = int(raw_input('Select 0..{}:\t'.format(len(ifaces)-1)))
                if iDev >= 0 and iDev < len(ifaces):
                    print "Selected:", ifaces[iDev]
                    monitor_traffic(ifaces[iDev])
                else:
                    print 'Invalid capture device !\n'
        except getopt.GetoptError:
            print 'Usage:', sys.argv[0], '-i <interface>'
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main(sys.argv[1:])

