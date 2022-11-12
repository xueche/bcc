#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcplife   Trace the lifespan of TCP sessions and summarize.
#           For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: tcplife [-h] [-C] [-S] [-p PID] [interval [count]]
#
# This uses the sock:inet_sock_set_state tracepoint if it exists (added to
# Linux 4.16, and replacing the earlier tcp:tcp_set_state), else it uses
# kernel dynamic tracing of tcp_set_state().
#
# While throughput counters are emitted, they are fetched in a low-overhead
# manner: reading members of the tcp_info struct on TCP close. ie, we do not
# trace send/receive.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# IDEA: Julia Evans
#
# 18-Oct-2016   Brendan Gregg   Created this.
# 29-Dec-2017      "      "     Added tracepoint support.

from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from time import strftime


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "foo"
#endif
#include <linux/tcp.h>
#include <linux/sched.h>
#include <linux/cgroup-defs.h>
#include <linux/kernfs.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct tcpconv4_data_t {
    u64 cgroup_id;
	u64 timeout_ns;
	u32 pid;
    u32 saddr;
	u32 lport; 
    u32 daddr; /* dest address */
    u32 dport;
	int err;
};
BPF_PERF_OUTPUT(tcpconv4_events);

struct tcpconv6_data_t {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
    u64 cgroup_id;
	u64 timeout_ns;
	u32 pid;
	u32 lport; 
    u32 dport;
	int err;
};

struct tcpcon_info_t {
	struct sock *sk;
	u32 port;
};

BPF_PERF_OUTPUT(tcpconv6_events);

BPF_HASH(whoami, u32, struct tcpcon_info_t);

int kprobe____inet_stream_connect(struct pt_regs *ctx, struct socket *sock, struct sockaddr *uaddr,
				int addr_len, int flags, int is_sendmsg)
{
	if (uaddr->sa_family != AF_INET && uaddr->sa_family != AF_INET6)
		return 0;
	
	if (sock->state == SS_CONNECTED || sock->state == SS_CONNECTING)
		return 0;

	//bpf_trace_printk("Enter\\n");	
	struct sock *sk = sock->sk;
	/*
	* notes: had best to initialise the tcpcon_info when declarin it.
        * because when updating the BPF_HASH, the ebpf verifier would check 
        * the value whether initialising, if not, it is a security risk.
	*/
	struct tcpcon_info_t tcpcon_info = {0};
	u32 pid = bpf_get_current_pid_tgid();
	
    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 lport = inet->inet_num;
    u16 dport;
    if (uaddr->sa_family == AF_INET) {
        /*
         * notes: why we don't use pointer type cast, because the size of struct sockaddr_in
         * is bigger than  struct sockaddr. when using "usin->sin_port", the ebpf verifier thinks
         * that is not legal. So we has to use bpf_probe_read() in here.
         */
        //struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
        struct sockaddr_in usin;
        bpf_probe_read(&usin, sizeof(struct sockaddr_in), uaddr);
        dport = ntohs(usin.sin_port);
     }
    else {
        //struct sockaddr_in6 *usin = (struct sockaddr_in6 *) uaddr;
        struct sockaddr_in6 usin;
        bpf_probe_read(&usin, sizeof(struct sockaddr_in6), uaddr);
        dport = ntohs(usin.sin6_port);
     }
    
    tcpcon_info.sk = sk;
	tcpcon_info.port = lport | (dport << 16);
    //tcpcon_info.port = 0;
	whoami.update(&pid, &tcpcon_info);

	return 0;
}

int kretprobe____inet_stream_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
//	bpf_trace_printk("ret=%d\\n", ret);
	u32 pid = bpf_get_current_pid_tgid();

	struct tcpcon_info_t *tcpcon_info_p = whoami.lookup(&pid);
	if (tcpcon_info_p == 0 )
		return 0;
	struct sock *sk = tcpcon_info_p->sk;
//	bpf_trace_printk("ret=%d\\n", ret);
	if (sk->sk_state == TCP_CLOSE) {
	    struct task_struct *task;
        struct cgroup_subsys_state * css;
        u64 cgroup_id;

        task = (struct task_struct *)bpf_get_current_task();
        css = (struct cgroup_subsys_state *)task->sched_task_group;
        cgroup_id = css->cgroup->kn->id.id;	
		u64 ts = bpf_ktime_get_ns();
		
        u16 lport  = (tcpcon_info_p->port) & (0xFFFF);
        u16 dport = (tcpcon_info_p->port) >> 16;
		u16 family = sk->__sk_common.skc_family;
		if (family == AF_INET) {
			/* filter for loopback session */
        		u64 addr = sk->__sk_common.skc_daddr;
      			if (addr == 0x0100007F) {
            			whoami.delete(&pid);
            			return 0;
        		}
			struct tcpconv4_data_t tcpconv4 = {.cgroup_id = cgroup_id,
				.pid = pid, .timeout_ns = ts, .err = ret};
			tcpconv4.lport = lport; 
			tcpconv4.dport = dport;
			tcpconv4.saddr = sk->__sk_common.skc_rcv_saddr;
			tcpconv4.daddr = sk->__sk_common.skc_daddr;
			tcpconv4_events.perf_submit(ctx, &tcpconv4, sizeof(tcpconv4));
		}
		else {
			struct tcpconv6_data_t tcpconv6 = {.cgroup_id = cgroup_id,
	
				.pid = pid, .timeout_ns = ts, .err = ret};
			tcpconv6.lport = lport;
			tcpconv6.dport = dport;
			bpf_probe_read(&tcpconv6.saddr, sizeof(tcpconv6.saddr),
            			sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		    bpf_probe_read(&tcpconv6.daddr, sizeof(tcpconv6.daddr),
            			sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
			tcpconv6_events.perf_submit(ctx, &tcpconv6, sizeof(tcpconv6));
		}
	}

	whoami.delete(&pid);

	return 0;
}
"""
#TASK_COMM_LEN = 16      # linux/sched.h

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("cgroup_id", ct.c_ulonglong),
        ("timeout_ns", ct.c_ulonglong),
		("pid", ct.c_uint),
        ("saddr", ct.c_uint),
        ("lport", ct.c_uint),
		("daddr", ct.c_uint),
		("dport", ct.c_uint),
		("err", ct.c_int)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
		("saddr", (ct.c_ulonglong * 2)),
		("daddr", (ct.c_ulonglong * 2)),
        ("cgroup_id", ct.c_ulonglong),
        ("timeout_ns", ct.c_ulonglong),
		("pid", ct.c_uint),
        ("lport", ct.c_uint),
		("dport", ct.c_uint),
		("err", ct.c_int)
    ]


#
# Setup output formats
#
# Don't change the default output (next 2 lines): this fits in 80 chars. I
# know it doesn't have NS or UIDs etc. I know. If you really, really, really
# need to add columns, columns that solve real actual problems, I'd start by
# adding an extended mode (-x) to included those columns.
#
header_string = "%-15s %-15s %-20s %-10s %-20s %-10s %-10s %-20s"
format_string = "%-15d %-15d %-20s %-10d %-20s %-10d %-10d %-20s"

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    global start_ts
    print("%-15s" % strftime("%H:%M:%S"), end="")
    print(format_string % (event.pid, event.cgroup_id, inet_ntop(AF_INET, pack("I", event.saddr)),
			event.lport, inet_ntop(AF_INET, pack("I", event.daddr)), event.dport, event.err, event.timeout_ns))

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    global start_ts
    print("%-15s" % strftime("%H:%M:%S"), end="")
    print(format_string % (event.pid, event.cgroup_id, inet_ntop(AF_INET6, event.saddr),
			event.lport, inet_ntop(AF_INET6, event.daddr), event.dport, event.err, event.timeout_ns))


# initialize BPF
b = BPF(text=bpf_text)
#b.trace_print()
print("%-15s" % ("TIME"), end="")
print(header_string % ( "PID", "CGROUP_ID", "SADDR", "SPORT", "DADDR", "DPORT", "ERRNO", "CLOSE_TIME"))

# read events
b["tcpconv4_events"].open_perf_buffer(print_ipv4_event, page_cnt=64)
b["tcpconv6_events"].open_perf_buffer(print_ipv6_event, page_cnt=64)


while 1:
    b.perf_buffer_poll()
