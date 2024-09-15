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
from scapy.config import conf

try:
    import scapy.libs.six as six

    if six.PY2:
        conf.contribs["CANSocket"] = {"use-python-can": True}
except ModuleNotFoundError:
    pass
from scapy.consts import LINUX

if not LINUX or conf.use_pypy:
    conf.contribs["CANSocket"] = {"use-python-can": True}

from scapy.scapypipes import WiresharkSink
from scapy.sendrecv import sniff, AsyncSniffer
from scapy.contrib.cansocket import CANSocket
from scapy.contrib.isotp import ISOTPSocket

from scapy.contrib.automotive.uds import UDS

from scapy.pipetool import CLIFeeder, ConsoleSink, PipeEngine

# end scapy setup

# logging setup
from logging import getLogger, WARN, INFO, DEBUG, CRITICAL

getLogger("scapy.contrib.automotive").setLevel(
    INFO
)  # set to DEBUG e.g. for more logging
getLogger("scapy.contrib.automotive.uds").setLevel(
    INFO
)  # set to DEBUG e.g. for more logging
getLogger("scapy.contrib.isotp").setLevel(INFO)  # set to DEBUG e.g. for more logging

# uncomment this for lightweight but kinda ugly logging
# can.bus.BusABC.RECV_LOGGING_LEVEL = WARN  # invasive bodge setting to log all received can frames when recv() active
# that ^^^ can.bus.BusABC.RECV_LOGGING_LEVEL bodge _works_ but not great.

PYTHON_CAN_INTERFACE = "slcan"
PYTHON_CAN_CHANNEL = "COM8"
PYTHON_CAN_BITRATE = 500_000


def candump_print_stderr(pkt, interface, channel):
    print(
        f"({pkt.time:010.06f}) {interface}{channel} {pkt.identifier:03x}#{pkt.data.hex().ljust(18)}  ; {str(pkt.data)}",
        file=sys.stderr,
        flush=True,
    )


feeder = CLIFeeder()
wire = WiresharkSink()
feeder > wire
p = PipeEngine(feeder)

# uncomment for CAN logging of the script in wireshark
#p.start()
time.sleep(6.0)  # wait for pipefeeder and wireshark to warm up


def sniff_action(pkt, interface, channel):
    feeder.send(pkt)
    if wire.f is not None:
        wire.f.flush()  # probably only flushes the _previous_ write but that's still better than nothing
    # uncomment for CAN logging of the script in candump format on stderr
    candump_print_stderr(pkt, interface, channel)
    return


sniff_csock = CANSocket(
    interface=PYTHON_CAN_INTERFACE,
    channel=PYTHON_CAN_CHANNEL,
    bitrate=PYTHON_CAN_BITRATE,
    receive_own_messages=False,
)

sniffer_started = threading.Event()
sniffer = AsyncSniffer(
    opened_socket=sniff_csock,
    prn=lambda pkt: sniff_action(pkt, PYTHON_CAN_INTERFACE, PYTHON_CAN_CHANNEL),
    store=0,
    started_callback=sniffer_started.set,
)
sniffer.start()
sniffer_started.wait(timeout=14.0)  # wait for sniffer to be running
# end logging setup

SEND_TO_ID = 0x7E1
RECV_FR_ID = SEND_TO_ID + 8
can_filters = None
if PYTHON_CAN_INTERFACE != 'pcan':  # workaround python-can bug in pcan driver: can_filters disrupts timing too much for reliable ISO-TP
    can_filters = [{'can_id': RECV_FR_ID, 'can_mask': 0x1FFFF}]

# example scapy automotive: ISOTP Send-Receive1. REPLACE THIS WITH YOUR SCRIPTS
# ---

csock = CANSocket(
    bustype=PYTHON_CAN_INTERFACE,
    channel=PYTHON_CAN_CHANNEL,
    bitrate=PYTHON_CAN_BITRATE,
    receive_own_messages=False,
    can_filters=can_filters,
)  # set 'can_mask' 0x000 to pass all traffic; set to 0x7ff to pass only matched traffic
with ISOTPSocket(csock, tx_id=SEND_TO_ID, rx_id=RECV_FR_ID, basecls=UDS) as isock:
    # there are a few examples of requests you could send here
    # UDS()/UDS_DSC(diagnosticSessionType=0x3
    # UDS()/UDS_SA(securityAccessType=0x1)
    # UDS()/UDS_SA(securityAccessType=0x2, securityKey=b'SKEY')
    # UDS()/UDS_WMBA(memorySizeLen=1, memoryAddressLen=4, memorySize1=2, memoryAddress4=0x0000057A, dataRecord=b'\x71\xcc')
    #
    # use these ones with ISOTPSocket(...,basecls=OBD) instead of =UDS above
    # OBD()/OBD_S01(pid=[0x00])
    # OBD()/OBD_S01(pid=[0x11]) # throttle position
    # OBD()/OBD_S01(pid=[0x0c]) # engine speed
    # OBD()/OBD_S09(iid=[0x0a]) # ecu name
    # OBD()/OBD_S03()
    #
    # let's use this one by default
    req = UDS(service=0x33) / bytes([0x12])  # a mysterious undocumented service
    
    resp = isock.sr1(req, timeout=14.0, retry=3)
    
    if resp is not None:
        resp.display()
        print("response bytes: " + str(bytes(resp)))
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

if wire.f is not None:
    wire.f.flush()
p.stop()
p.wait_and_stop()
