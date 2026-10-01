"""HTTP/3 client for the QUIC interop test.

Plain sockets rather than aioquic's asyncio helper, because the raw path can
print a machine-readable marker per event. What the test asserts on is those
lines, not the absence of an exception: a client that times out quietly would
otherwise be indistinguishable from a server that answered.

The certificate is the self-signed test pair, so verification is off. This
exercise is about QUIC and HTTP/3, not chain building, which the TLS interop
tests already cover against OpenSSL.

Run standalone against a listening server for diagnosis:

    python3 aioquic_client.py <port>
"""

import socket
import ssl
import sys
import time

from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

PORT = int(sys.argv[1])
PATH = sys.argv[2] if len(sys.argv) > 2 else "/ping"
DEADLINE_S = 20

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 0))
sock.settimeout(0.2)

config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
config.verify_mode = ssl.CERT_NONE

quic = QuicConnection(configuration=config, original_destination_connection_id=None)
quic.connect(("127.0.0.1", PORT), now=time.time())

h3 = H3Connection(quic)
h3.send_headers(
    stream_id=0,
    headers=[
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"127.0.0.1"),
        (b":path", PATH.encode()),
    ],
    end_stream=True,
)

status = None
body = b""
done = False
deadline = time.time() + DEADLINE_S

while time.time() < deadline and not done:
    for data, addr in quic.datagrams_to_send(now=time.time()):
        sock.sendto(data, addr)
    try:
        data, addr = sock.recvfrom(65535)
    except socket.timeout:
        continue
    try:
        quic.receive_datagram(data, addr, now=time.time())
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        print("RECEIVE_ERROR %s" % (type(exc).__name__,))
        break

    while True:
        event = quic.next_event()
        if event is None:
            break
        name = type(event).__name__
        if name == "ConnectionTerminated":
            print("TERMINATED %s" % (getattr(event, "reason_phrase", ""),))
            done = True
        elif name == "HandshakeCompleted":
            print("HANDSHAKE completed")
        for h3_event in h3.handle_event(event):
            if isinstance(h3_event, HeadersReceived):
                for key, value in h3_event.headers:
                    if key == b":status":
                        status = int(value)
            elif isinstance(h3_event, DataReceived):
                body += h3_event.data
                if h3_event.stream_ended:
                    done = True

print("STATUS %s" % (status,))
print("BODY %s" % (body.decode("utf-8", "replace"),))
print("RESULT %s" % ("ok" if done and status else "timeout",))