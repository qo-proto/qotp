# QOTP - Quite OK Transport Protocol

⚠️ **Warning**: Protocol format is not final and may change.

A UDP-based transport protocol with an opinionated approach, similar to QUIC but focused on reasonable defaults over configurability. Goals: lower complexity, simplicity, security, and reasonable performance.

QOTP is P2P-friendly, supporting UDP hole punching, multi-homing (packets from different source addresses), out-of-band key exchange, no TIME_WAIT state, and single socket for multiple connections.

## Key Design Choices

- **Single crypto suite**: curve25519/chacha20poly1305 (vs SSL/TLS with 57+ RFCs)
- **Always encrypted**: No plaintext option, no key renegotiation
- **0-RTT option**: User chooses between 0-RTT (no perfect forward secrecy) or 1-RTT (with perfect forward secrecy)
- **BBR congestion control**: Estimates network capacity via bottleneck bandwidth and RTT
- **Connection-level flow control**: Congestion control at connection level, not per-stream
- **Simple teardown**: FIN/ACK with timeout
- **Compact**: Goal < 3k LoC (currently ~2.8k LoC source)

In QOTP, there is 1 supported crypto algorithm (curve25519/chacha20-poly1305) as in contrast to TLS with
many options. It is mentioned [here](https://www.cs.auckland.ac.nz/~pgut001/pubs/bollocks.pdf) that there
are 60 RFCs for TLS. However, the [Wikipedia](https://en.wikipedia.org/wiki/Transport_Layer_Security) site
only mentions 9 primary RFCs and 48 extensions and informational RFCs, totalling 57 RFC.

## Similar Projects

* https://github.com/Tribler/utp4j
* https://github.com/quic-go/quic-go
* https://github.com/skywind3000/kcp (no encryption)
* https://github.com/johnsonjh/gfcp (golang version)
* https://eprints.ost.ch/id/eprint/846/
* https://eprints.ost.ch/id/eprint/879/ (https://github.com/stalder-n/lrp2p-go)
* https://eprints.ost.ch/id/eprint/979/

## Core Assumptions

* Max RTT: Up to 30 seconds connection timeout (no hard RTT limit, but suspicious RTT > 30s logged)
* Packet identification: Stream offset (24 or 48-bit) + length (16-bit)
* Default Max Data Transfer: 1400 bytes (configurable)
* Buffer capacity: 16MB send + 16MB receive (configurable constants)
* Crypto sequence space: 48-bit sequence number + 47-bit epoch = 2^95 total space
  * Separate from transport layer stream offsets
  * Rollover at 2^48 packets (not bytes) increments epoch counter
  * At 2^95 exhaustion: ~5 billion ZB sent, requires manual reconnection
* Transport sequence space: 24-bit (16MB range) or 48-bit (256TB range) stream offsets per stream
  * Automatically uses 48-bit when offset > 0xFFFFFF (16MB)
  * Multiple independent streams per connection

## Protocol Specification

### Message Flow

**Flow 1: In-band Key Exchange (No Prior Keys)**

```
Sender → Receiver: InitSnd (unencrypted, 1400 bytes min)
  - pubKeyEpSnd + (pubKeyIdSnd)
  - Padded to prevent amplification

Receiver → Sender: InitRcv (encrypted with ECDH)
  - pubKeyEpRcv + (pubKeyIdRcv)
  - Can contain payload (perfect forward secrecy)

Both: Data messages (encrypted with shared secret)
```

**Flow 2: Out-of-band Keys (0-RTT)**

```
Sender → Receiver: InitCryptoSnd (encrypted - [prvKeyEpSnd + pubKeyIdRcv], non-PFS)
  - pubKeyEpSnd + (pubKeyIdSnd)
  - Can contain payload
  - 1400 bytes min with padding

Receiver → Sender: InitCryptoRcv (encrypted - [pubKeyEpSnd + prvKeyEpRcv], PFS)
  - pubKeyEpRcv
  - Can contain payload

Both: Data messages (encrypted with PFS shared secret)
```

### Encryption Layer

#### Header Format (1 byte)

```
Bits 0-4: Version (5 bits, currently 0)
Bits 5-7: Message Type (3 bits)
```

**Message Types**:
- `000` (0): InitSnd - Initial handshake from sender
- `001` (1): InitRcv - Initial handshake reply from receiver  
- `010` (2): InitCryptoSnd - Initial with crypto from sender
- `011` (3): InitCryptoRcv - Initial with crypto reply from receiver
- `100` (4): Data - All data messages

#### Constants

```
CryptoVersion       = 0
MacSize             = 16 bytes (Poly1305)
SnSize              = 6 bytes (48-bit sequence number)
MinProtoSize        = 8 bytes (minimum payload)
PubKeySize          = 32 bytes (X25519)
HeaderSize          = 1 byte
ConnIdSize          = 8 bytes
MsgInitFillLenSize  = 2 bytes

MinInitRcvSizeHdr       = 73 bytes (header + connId + 2 pubkeys)
MinInitCryptoSndSizeHdr = 65 bytes (header + 2 pubkeys)
MinInitCryptoRcvSizeHdr = 41 bytes (header + connId + pubkey)
MinDataSizeHdr          = 9 bytes (header + connId)
FooterDataSize          = 22 bytes (6 SN + 16 MAC)
MinPacketSize           = 39 bytes (9 + 22 + 8)

Default Max Data Transfer             = 1400 bytes
Send Buffer Capacity    = 16 MB
Receive Buffer Capacity = 16 MB
```

### Message Structures

#### InitSnd (Type 000, Min: 1400 bytes)

Unencrypted, no data payload. Minimum 1400 bytes prevents amplification attacks.

```
Byte 0:       Header (version=0, type=000)
Bytes 1-32:   Public Key Ephemeral Sender (X25519)
              First 8 bytes = Connection ID
Bytes 33-64:  Public Key Identity Sender (X25519)
Bytes 65+:    Padding to 1400 bytes
```

**Connection ID**: First 64 bits of pubKeyEpSnd used as temporary connection ID.

#### InitRcv (Type 001, Min: 103 bytes)

Encrypted with ECDH(prvKeyEpRcv, pubKeyEpSnd). Achieves perfect forward secrecy.

```
Byte 0:       Header (version=0, type=001)
Bytes 1-8:    Connection ID (from InitSnd)
Bytes 9-40:   Public Key Ephemeral Receiver (X25519)
Bytes 41-72:  Public Key Identity Receiver (X25519)
Bytes 73-78:  Encrypted Sequence Number (48-bit)
Bytes 79+:    Encrypted Payload (min 8 bytes)
Last 16:      MAC (Poly1305)
```

After InitRcv, connection ID becomes: `pubKeyIdRcv[0:8] XOR pubKeyIdSnd[0:8]`

#### InitCryptoSnd (Type 010, Min: 1400 bytes)

Encrypted with ECDH(prvKeyEpSnd, pubKeyIdRcv). No perfect forward secrecy for first message.

```
Byte 0:       Header (version=0, type=010)
Bytes 1-32:   Public Key Ephemeral Sender (X25519)
              First 8 bytes = Connection ID
Bytes 33-64:  Public Key Identity Sender (X25519)
Bytes 65-70:  Encrypted Sequence Number (48-bit)
Bytes 71-72:  Filler Length (16-bit, encrypted)
Bytes 73+:    Filler (variable, encrypted)
Bytes X+:     Encrypted Payload (min 8 bytes)
Last 16:      MAC (Poly1305)
Total:        Padded to 1400 bytes
```

#### InitCryptoRcv (Type 011, Min: 71 bytes)

Encrypted with ECDH(prvKeyEpRcv, pubKeyEpSnd). Achieves perfect forward secrecy.

```
Byte 0:       Header (version=0, type=011)
Bytes 1-8:    Connection ID (from InitCryptoSnd)
Bytes 9-40:   Public Key Ephemeral Receiver (X25519)
Bytes 41-46:  Encrypted Sequence Number (48-bit)
Bytes 47+:    Encrypted Payload (min 8 bytes)
Last 16:      MAC (Poly1305)
```

#### Data (Type 100, Min: 39 bytes)

All subsequent data messages after handshake.

```
Byte 0:       Header (version=0, type=100)
Bytes 1-8:    Connection ID
Bytes 9-14:   Encrypted Sequence Number (48-bit)
Bytes 15+:    Encrypted Payload (min 8 bytes)
Last 16:      MAC (Poly1305)
```

### Double Encryption Scheme

QOTP uses deterministic double encryption for sequence numbers and payload:

**Encryption Process**:

1. **First Layer** (Payload):
   - Nonce: 12 bytes deterministic
     - Bytes 0-5: Epoch (48-bit)
     - Bytes 6-11: Sequence number (48-bit)
     - Byte 0, bit 7 (MSB): 1=sender, 0=receiver (prevents nonce collision)
   - Encrypt payload with ChaCha20-Poly1305
   - AAD: header (unencrypted packet prefix)
   - Output: ciphertext + 16-byte MAC

2. **Second Layer** (Sequence Number):
   - Nonce: First 24 bytes of first-layer ciphertext
   - Encrypt sequence number (bytes 6-11 of deterministic nonce) with XChaCha20-Poly1305
   - Take first 6 bytes only (discard MAC)

**Decryption Process**:

1. Extract encrypted sequence number (first 6 bytes after header)
2. Use first 24 bytes of ciphertext as nonce
3. Decrypt 6-byte sequence number with XChaCha20 (no MAC verification)
4. Reconstruct deterministic nonce with decrypted sequence number
5. Try decryption with epochs: current, current-1, current+1
6. Verify MAC on payload - any tampering fails authentication

**Epoch Handling**:

- Sequence number rolls over at 2^48 packets (not bytes)
- Epoch increments on rollover (47-bit; bit 7 of byte 0 reserved for direction)
- Decryption tries 3 epochs to handle reordering near boundaries
- Total space: 2^95 ≈ 40 ZB (exhaustion would require resending all human data 28M times)

### Transport Layer (Payload Format)

After decryption, payload contains transport header + data. Min 8 bytes total.

#### Payload Header Format

**Byte 0 (Header byte):**
```
Bits 0-4: Protocol Version (5 bits, currently 0)
Bits 5-6: Message Type (2 bits)
Bit 7:    Offset Size (0 = 24-bit, 1 = 48-bit)
```

**Message Type Encoding (bits 5-6):**

| Type | IsClose | Has ACK | Description |
|------|---------|---------|-------------|
| `00` | No      | Yes     | DATA with ACK |
| `01` | No      | No      | DATA without ACK |
| `10` | Yes     | Yes     | CLOSE with ACK |
| `11` | Yes     | No      | CLOSE without ACK |

**Message Type Semantics:**

- **Type `00` (DATA with ACK)**: 
  - Contains acknowledgment for received data
  - If `userData == nil` (not empty array): ACK-only packet, no stream data header
  - If `userData == []byte{}` (empty array): PING packet with stream data header

- **Type `01` (DATA without ACK)**:
  - Pure data transmission, no acknowledgment piggybacked
  - If `userData == []byte{}` (empty array): PING packet with stream data header

- **Type `10` (CLOSE with ACK)**:
  - Notifies peer that stream is closing at specified offset
  - Includes acknowledgment for received data

- **Type `11` (CLOSE without ACK)**:
  - Notifies peer that stream is closing at specified offset
  - No acknowledgment piggybacked

**PING packets:**
- Indicated by `userData == []byte{}` (empty array, not nil)
- Always include stream data header (StreamID + StreamOffset)
- Used for keepalive and RTT measurement
- Require acknowledgment but are not retransmitted if lost

**ACK-only packets:**
- Indicated by `userData == nil` in type `00` messages
- Omit stream data header to save space
- Only contain ACK section

#### Packet Structure

**With ACK + Stream Data (types 00, 01, 10, 11 with userData != nil):**
```
Byte 0:           Header
Bytes 1-4:        ACK Stream ID (32-bit) [if type 00 or 10]
Bytes 5-7/10:     ACK Offset (24 or 48-bit) [if type 00 or 10]
Bytes 8-9/11-12:  ACK Length (16-bit) [if type 00 or 10]
Byte 10/13:       ACK Receive Window (8-bit, encoded) [if type 00 or 10]
Bytes X-X+3:      Stream ID (32-bit)
Bytes X+4-X+6/9:  Stream Offset (24 or 48-bit)
Bytes X+7/10+:    User Data (can be empty for PING)
```

**ACK-only (type 00 with userData == nil):**
```
Byte 0:           Header
Bytes 1-4:        ACK Stream ID (32-bit)
Bytes 5-7/10:     ACK Offset (24 or 48-bit)
Bytes 8-9/11-12:  ACK Length (16-bit)
Byte 10/13:       ACK Receive Window (8-bit, encoded)
```

**Data-only (type 01 with userData):**
```
Byte 0:           Header
Bytes 1-4:        Stream ID (32-bit)
Bytes 5-7/10:     Stream Offset (24 or 48-bit)
Bytes 8/11+:      User Data
```

#### Receive Window Encoding

The 8-bit receive window field encodes buffer capacity from 0 to ~896GB using logarithmic encoding with 8 substeps per power of 2:

### Flow Control and Congestion

#### BBR Congestion Control

**State Machine**:

```
Startup → Drain/Normal → Probe → Normal
  ↓
Always: RTT inflation check
```

**Pacing Gains**:
- Startup: 277% (2.77x) - aggressive growth
- Normal: 100% (1.0x) - steady state
- Drain: 75% (0.75x) - reduce queue after startup
- Probe: 125% (1.25x) - periodic bandwidth probing
- DupAck: 90% (0.9x) - back off on duplicate ACK

**State Transitions**:

1. **Startup → Normal**: When bandwidth stops growing (3 consecutive samples without increase)
2. **Normal → Drain**: When RTT inflation > 150% of minimum
3. **Normal → DupAck**: On duplicate ACK (reduce bandwidth to 98%)
4. **Normal → Probe**: Every 8 × RTT_min (probe for more bandwidth)

**Measurements**:

```go
SRTT = (7/8) × SRTT + (1/8) × RTT_sample
RTTVAR = (3/4) × RTTVAR + (1/4) × |SRTT - RTT_sample|
RTT_min = min(RTT_samples) over 10 seconds
BW_max = max(bytes_acked / RTT_min)
```

**Pacing Calculation**:

```
pacing_interval = (packet_size × 1e9) / (BW_max × gain_percent / 100)
```

If no bandwidth estimate: use `SRTT / 10` or fallback to 10ms.

#### Retransmission (RTO)

```
RTO = SRTT + 4 × RTTVAR
RTO = clamp(RTO, 100ms, 2000ms)
Default RTO = 200ms (when no SRTT)

Backoff: RTO_i = RTO × 2^(i-1)
Max retries: 4 (total 5 attempts)
Timeout after ~5 seconds total
```

**Example timing**:
- Attempt 1: t=0
- Attempt 2: t=250ms
- Attempt 3: t=687ms
- Attempt 4: t=1452ms
- Attempt 5: t=2791ms
- Fail: t=5134ms

#### Flow Control

**Receive Window**: 
- Advertised in each ACK
- Calculated as: `buffer_capacity - current_buffer_usage`
- Encoded logarithmically (8-bit → 896GB range)
- Sender respects: `data_in_flight + packet_size ≤ rcv_window`

**Pacing**: 
- Sender tracks `next_write_time`
- Waits until `now ≥ next_write_time` before sending
- Even ACK-only packets respect pacing (can send early if needed)

### Stream Management

#### Stream Lifecycle

```
Open → Active → Close_Requested → Closed (30s timeout)
```

**Stream States**:
- `Open`: Normal read/write operations
- `CloseRequested`: Close initiated, waiting for offset acknowledgment
- `Closed`: All data up to close offset delivered, 30-second grace period

#### Bidirectional Close Protocol

QOTP implements a clean bidirectional close mechanism similar to TCP FIN, ensuring both sides gracefully terminate:

**Initiator Side (calls Close() first)**:
1. Marks `closeAtOffset` in send buffer at current write position
2. Continues sending queued data up to `closeAtOffset`
3. When `closeAtOffset` reached, sends CLOSE packet (may be empty if no data queued)
4. Marks `rcvCloseAtOffset` in receive buffer at current read position
5. Waits for CLOSE response from peer
6. Upon receiving peer's CLOSE: marks `rcvCloseAtOffset` in receive buffer
7. When read reaches `rcvCloseAtOffset`: receive direction closed
8. When both `rcvClosed` and `sndClosed`: stream fully closed

**Responder Side (receives CLOSE first)**:
1. Receives CLOSE packet at offset X
2. Marks `rcvCloseAtOffset = X` in receive buffer
3. Marks `sndCloseAtOffset` in send buffer at current write position
4. When send buffer reaches `sndCloseAtOffset` AND all ACKs received (including for peer's CLOSE): send direction ready to close
5. Sends CLOSE response packet
6. When read reaches offset X: receive direction closed
7. When both `rcvClosed` and `sndClosed`: stream fully closed

**Key Properties**:
- Both directions close independently (half-close supported)
- CLOSE packets must be ACKed like regular data
- Stream fully closed only when both directions closed
- Empty CLOSE packets allowed when no data pending
- No grace period after bidirectional close (immediate cleanup)

**Example Flow**:
```
A writes 100 bytes → calls Close()
A.sndCloseOffset = 100
A sends DATA[0-100] + CLOSE

B receives CLOSE at offset 100
B.rcvCloseOffset = 100
B.sndCloseOffset = 50 (current position)
B sends DATA[0-50] + CLOSE

A receives CLOSE at offset 50
A.rcvCloseOffset = 50
When A reads to offset 50: A.rcvClosed = true
When A gets ACK for offset 100: A.sndClosed = true
→ A fully closed

When B reads to offset 100: B.rcvClosed = true  
When B gets ACK for offset 50: B.sndClosed = true
→ B fully closed
```

**Grace Period**: 30 seconds (ReadDeadLine) only on receiver side to handle late packets and retransmissions.

### Connection Management

**Connection ID**: 
- Initial: First 64 bits of ephemeral public key
- Final: `pubKeyIdRcv[0:8] XOR pubKeyIdSnd[0:8]`
- Enables multi-homing (packets from different source addresses)

**Connection Timeout**: 
- 30 seconds of inactivity (no packets sent or received)
- Automatic cleanup after timeout

**Single Socket**: 
- All connections share one UDP socket
- No TIME_WAIT state
- Scales to many short-lived connections

### Buffer Management

**Send Buffer** (`SendBuffer`):
- Capacity: 16 MB (configurable)
- Tracks: queued data, in-flight data, ACKed data
- Per-stream accounting
- `userData`: queued data not yet sent
- `dataInFlightMap`: sent but not ACKed (key: offset+length)
- Retransmission: oldest unACKed packet on RTO

**Receive Buffer** (`ReceiveBuffer`):
- Capacity: 16 MB (configurable)
- Handles: out-of-order delivery, overlapping segments
- Per-stream segments stored in sorted map
- Deduplication: checks against `nextInOrderOffsetToWaitFor`
- Overlap handling: validates matching data in overlaps

**Packet Key Encoding** (64-bit):
```
Bits 0-15:  Length (16-bit)
Bits 16-63: Offset (48-bit)
```

Enables O(1) in-flight packet tracking and ACK processing.

## Overhead Analysis

**Crypto Layer Overhead**:
- InitSnd: 1400 bytes (no data, padding)
- InitRcv: 103+ bytes (73 header + 6 SN + 16 MAC + ≥8 payload)
- InitCryptoSnd: 1400 bytes (includes padding)
- InitCryptoRcv: 63+ bytes (41 header + 6 SN + 16 MAC + ≥8 payload)
- Data: 39+ bytes (9 header + 6 SN + 16 MAC + ≥8 payload)

**Transport Layer Overhead** (variable):
- No ACK, 24-bit offset: 8 bytes
- No ACK, 48-bit offset: 11 bytes
- With ACK, 24-bit offset: 18 bytes
- With ACK, 48-bit offset: 24 bytes

**Total Minimum Overhead** (Data message with payload):
- Best case: 39 bytes (9 + 6 + 16 + 8 transport header)
- Typical: 39-47 bytes for data packets
- 1400-byte packet: ~2.8-3.4% overhead

## Implementation Details

### Data Structures

**LinkedMap**: O(1) insertion, deletion, lookup, and Next/Prev traversal. Used for connection and stream maps.

### Thread Safety

All buffer operations protected by mutexes:
- `SendBuffer.mu`: Protects send buffer operations
- `ReceiveBuffer.mu`: Protects receive buffer operations
- `Conn.mu`: Protects connection state
- `Listener.mu`: Protects listener state

### Error Handling

**Crypto Errors**: 
- Authentication failures logged and dropped silently
- Malformed packets logged and dropped
- Epoch mismatches handled with ±1 epoch tolerance

**Buffer Full**:
- Send: `Write()` returns partial bytes written
- Receive: Packet dropped with `RcvInsertBufferFull`

**Connection Errors**:
- RTO exhausted: Close connection
- 30-second inactivity: Close connection
- Invalid state transitions: Close connection

## Usage Example

```go
// Server
listener, _ := qotp.Listen(qotp.WithListenAddr("127.0.0.1:8888"))
defer listener.Close()

listener.Loop(func(stream *qotp.Stream) bool {
    if stream == nil {
        return true // No data yet
    }
    data, err := stream.Read()
    if err != nil {
        return false // Exit loop
    }
    if len(data) > 0 {
        stream.Write([]byte("response"))
        stream.Close()
    }
    return true
})

// Client (in-band key exchange)
listener, _ := qotp.Listen()
conn, _ := listener.DialString("127.0.0.1:8888")
stream := conn.Stream(0)
stream.Write([]byte("hello"))

// Client (out-of-band keys, 0-RTT)
pubKeyHex := "0x1234..." // Receiver's public key
conn, _ := listener.DialWithCryptoString("127.0.0.1:8888", pubKeyHex)
```

## Contributing

Protocol is experimental. Contributions welcome but expect breaking changes.