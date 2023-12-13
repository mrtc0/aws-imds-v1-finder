from bcc import BPF
import os

def is_imds_v2_request(pkt):
    IMDSV2_TOKEN_PREFIX = "x-aws-ec2-metadata-token"
    is_v2 = False

    if IMDSV2_TOKEN_PREFIX in pkt.lower():
        is_v2 = True

    return is_v2

def print_imds_event(cpu, data, size):
    event = b["imds_events"].event(data)
    pkt = event.pkt[:event.pkt_size].decode()

    if is_imds_v2_request(pkt):
        return

    print("IMDS v1 Request found: PID: %d, Comm: %s, Parent Comm: %s\n" % (event.pid, event.comm.decode(), event.parent_comm.decode()))


if(__name__ == "__main__"):
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script. exited.\n")

    b = BPF("bpf.c")
    try:
        b.attach_kprobe(event="__sock_sendmsg", fn_name="trace_sock_sendmsg")
    except:
        print("Failed to attach kprobe to __sock_sendmsg, using older kernel implementation")
        b.attach_kprobe(event="sock_sendmsg", fn_name="trace_sock_sendmsg")

    b["imds_events"].open_perf_buffer(print_imds_event)
    print("Tracing IMDS v1 requests...")

    while 1:
        try:
            b.perf_buffer_poll()
        except ValueError:
            continue

        except KeyboardInterrupt:
            exit()
