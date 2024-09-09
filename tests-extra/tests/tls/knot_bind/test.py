#!/usr/bin/env python3

'''Test of zone transfers over TLS between Bind and Knot.'''

from dnstest.test import Test
from dnstest.utils import *
import random
import subprocess

t = Test(tls=True, tsig=True) # TSIG needed to skip weaker ACL rules

master = t.server("knot")
slave = t.server("bind")
zones = t.zone("example.") #t.zone_rnd(1, records=50) + \
            #t.zone_rnd(1, records=500) + \
            #t.zone_rnd(1, records=1000)

t.link(zones, master, slave)

#for z in rnd_zones:
#    master.dnssec(z).enable = True

#if master.valgrind:
#    slave.quic_idle_close_timeout = 10 # for DoQ xfrs
#    master.tcp_io_timeout = 10000
#    slave.tcp_io_timeout = 10000
#    master.tcp_remote_io_timeout = 10000
#    slave.tcp_remote_io_timeout = 10000
#if slave.valgrind:
#    master.quic_idle_close_timeout = 10 # for sending DoQ notify

def upd_check_zones(master, slave, zones, prev_serials):
    for z in zones:
        master.random_ddns(z, allow_empty=False)
    serials = slave.zones_wait(zones, prev_serials)
    t.xfr_diff(master, slave, zones, prev_serials)
    return serials

t.start()

tcpdump_pcap = t.out_dir + "/traffic.pcap"
tcpdump_fout = t.out_dir + "/tcpdump.out"
tcpdump_ferr = t.out_dir + "/tcpdump.err"

tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "lo", "-w", tcpdump_pcap,
                                 "port", str(master.tls_port), "or", "port", str(slave.tls_port)],
                                stdout=open(tcpdump_fout, mode="a"), stderr=open(tcpdump_ferr, mode="a"))

try:
    serials = master.zones_wait(zones)
    slave.zones_wait(zones, serials, equal=True, greater=False)
    t.xfr_diff(master, slave, zones)

    master.fill_cert_key()
    slave.gen_confile()
    slave.reload()
    t.sleep(10)
    serials = upd_check_zones(master, slave, zones, serials)

finally:
    tcpdump_proc.terminate()

t.end()
