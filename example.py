import sys
import signal
import threading
import time

import can
# scapy setup
# # this works

# from scapy.all import *
# load_layer("can")
# conf.contribs['CANSocket'] = {'use-python-can' : True}
# load_contrib('cansocket')

# but this is more explicit
import scapy.libs.six as six
from scapy.config import conf
from scapy.consts import LINUX
from scapy.scapypipes import WiresharkSink

from scapy.sendrecv import sniff, AsyncSniffer

if six.PY2 or not LINUX or conf.use_pypy:
    conf.contribs['CANSocket'] = {'use-python-can': True}

from scapy.contrib.cansocket import CANSocket, PYTHON_CAN  # noqa: E402
from scapy.contrib.isotp import ISOTPSocket

from scapy.contrib.automotive.uds import UDS

from scapy.pipetool import CLIFeeder, ConsoleSink, PipeEngine
# end scapy setup

# logging setup
from logging import getLogger, WARN, INFO, DEBUG, CRITICAL

getLogger("scapy.contrib.automotive.uds").setLevel(INFO)  # set to DEBUG e.g. for more logging
getLogger("scapy.contrib.isotp").setLevel(INFO)  # set to DEBUG e.g. for more logging

# uncomment this for lightweight but kinda ugly logging
# can.bus.BusABC.RECV_LOGGING_LEVEL = WARN  # invasive bodge setting to log all received can frames when recv() active
# that ^^^ can.bus.BusABC.RECV_LOGGING_LEVEL bodge _works_ but not great.

def candump_print_stderr(pkt, interface, channel):
    print(
        f'({pkt.time:010.06f}) {interface}{channel} {pkt.identifier:03x}#{pkt.data.hex().ljust(18)}  ; {str(pkt.data)}',
        file=sys.stderr, flush=True)

source = CLIFeeder()
wire = WiresharkSink()
source > wire
p = PipeEngine(source)

# uncomment for CAN logging of the script in wireshark
p.start()

def sniff_action(pkt, interface, channel):
    source.send(pkt)
    # uncomment for CAN logging of the script in candump format on stderr
    candump_print_stderr(pkt, interface, channel)
    return

sniff_csock = CANSocket(bustype="cantact", channel="0", receive_own_messages=False)

sniffer_started = threading.Event()
sniffer = AsyncSniffer(opened_socket=sniff_csock,
                       prn=lambda pkt: sniff_action(pkt, 'cantact', '0'),
                       store=0,
                       started_callback=sniffer_started.set
                       )
sniffer.start()
sniffer_started.wait(timeout=7.0)  # wait for sniffer to be running
# end logging setup

# example scapy automotive: ISOTP Send-Receive1. REPLACE THIS WITH YOUR SCRIPTS
csock = CANSocket(bustype="cantact", channel="0", receive_own_messages=False)
with ISOTPSocket(csock, tx_id=0x7e1, rx_id=0x7e9, basecls=UDS) as isock:
    resp = isock.sr1(UDS(service=0x33) / bytes([0x12]), timeout=0.250, retry=3)  # retry is a good idea
    if resp is not None:
        print("response: " + str(bytes(resp)))
    else:
        print("ERROR: NO RESPONSE")

# ---
sniffer.stop()
sniffer.join()

csock.close()
## scapy / python-can BUG WORKAROUND: the end of the `with` block above .close()es the `csock2` which also deletes and
# closes the underlying python-can interface. If we don't monkey-patch the `low_csock.closed` then the result will be a
# deep stacktrace while python is shutting down later
csock.closed = True
csock.can_iface._is_shutdown = True

sniff_csock.close()
## scapy / python-can BUG WORKAROUND: the end of the `with` block above .close()es the `csock2` which also deletes and
# closes the underlying python-can interface. If we don't monkey-patch the `low_csock.closed` then the result will be a
# deep stacktrace while python is shutting down later
sniff_csock.closed = True
sniff_csock.can_iface._is_shutdown = True

p.stop()
p.wait_and_stop()
