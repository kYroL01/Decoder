[![Generic badge](https://img.shields.io/badge/ANSI-C-green.svg)](Ansi-C)
[![Generic badge](https://img.shields.io/badge/Networking-orange.svg)](Networking)
[![Generic badge](https://img.shields.io/badge/DPI-blue.svg)](https://en.wikipedia.org/wiki/Deep_packet_inspection)

# Decoder

Standalone project for protocol dissectors testing.

Decoder captures packets (live interface or pcap file), parses L2/L3/L4 headers, and dispatches payloads to protocol-specific dissectors.

## Build and Run

```bash
make build
sudo ./decoder -i <device>
# or
sudo ./decoder -p <pcap_file>
```

## Architecture

The project is organized around a packet processing pipeline:

- **Input layer (`decoder.c`)**: parses CLI options, opens live/offline pcap handle, initializes flow context, registers dissectors, and starts `pcap_loop`.
- **Packet parsing layer (`functions.c`)**: callback parses datalink/network/transport headers, computes payload and metadata (IP version, ports, protocol), and updates session statistics.
- **Dissector engine (`dissector.c`)**: keeps a registry of dissectors and selects the right one by L4 protocol + port.
- **Protocol wrappers (`proto_wrappers.c`)**: adapter functions for TLS, RTP, RTCP, RTSP, GTP, NGCP, and Diameter parsers.
- **Protocol parsers (`*.c`)**: protocol-specific decoding and output formatting.
- **Flow/state & stats (`functions.c`, `tls_ssl.c`, `uthash`)**: flow tracking for stateful parsing (notably TLS) and end-of-run reporting.

### Component Flow (ASCII)

```text
   CLI Args (-i / -p)
           |
           v
   decoder.c (main)
           |
           v
   pcap_loop(callback_proto)
           |
           v
 functions.c
 [L2/L3/L4 parsing + payload extraction]
           |
           v
 dissector_run() in dissector.c
 [registry match by proto/port]
           |
           v
 proto_wrappers.c
 [TLS/RTCP/RTP/RTSP/GTP/NGCP/DIAMETER]
           |
           v
 protocol parser modules (*.c)
           |
           v
 decoded output + flow/state updates + stats
```

[TODO list](https://github.com/kYroL01/Decoder/blob/master/TODO.md)

---

[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-PayPal-00457C?logo=paypal&logoColor=white)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=fci1908%40gmail.com&currency_code=USD)

PayPal: **fci1908@gmail.com**
