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
- **MTU configuration**: No MTU discover, only MTU configuratio, default to 1400 (QUIC has 1200)
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
* Default MTU: 1400 bytes (configurable)
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
  - pubKeyEpSnd + pubKeyIdSnd
  - Padded to prevent amplification

Receiver → Sender: InitRcv (encrypted with ECDH)
  - pubKeyEpRcv + pubKeyIdRcv
  - Can contain payload (perfect forward secrecy)

Both: Data messages (encrypted with shared secret)
```

**Flow 2: Out-of-band Keys (0-RTT)**

```
Sender → Receiver: InitCryptoSnd (encrypted, non-PFS)
  - pubKeyEpSnd + pubKeyIdSnd
  - Can contain payload
  - 1400 bytes min with padding

Receiver → Sender: InitCryptoRcv (encrypted, PFS)
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

MinInitRcvSizeHdr       = 65 bytes (header + connId + 2 pubkeys)
MinInitCryptoSndSizeHdr = 65 bytes (header + 2 pubkeys)
MinInitCryptoRcvSizeHdr = 41 bytes (header + connId + pubkey)
MinDataSizeHdr          = 9 bytes (header + connId)
FooterDataSize          = 22 bytes (6 SN + 16 MAC)
MinPacketSize           = 39 bytes (9 + 22 + 8)

Default MTU             = 1400 bytes
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
     - Bit 0 (MSB): 0=receiver, 1=sender (prevents nonce collision)
   - Encrypt payload with ChaCha20-Poly1305
   - AAD: header + crypto data
   - Output: ciphertext + 16-byte MAC

2. **Second Layer** (Sequence Number):
   - Nonce: First 24 bytes of first-layer ciphertext (random)
   - Encrypt sequence number with XChaCha20-Poly1305
   - Take first 6 bytes only (discard MAC)

**Decryption Process**:

1. Extract first 24 bytes of first-layer ciphertext as nonce
2. Decrypt 6-byte sequence number with XChaCha20-Poly1305
3. Reconstruct deterministic nonce with decrypted sequence number
4. Try decryption with epochs: current, current-1, current+1
5. Verify MAC - any tampering fails authentication

**Epoch Handling**:

- Sequence number rolls over at 2^48 (256 TB)
- Epoch increments on rollover (47-bit, last bit for sender/receiver)
- Decryption tries 3 epochs to handle reordering near boundaries
- Total space: 2^95 ≈ 40 ZB (exhaustion would require resending all human data 28M times)

### Transport Layer (Payload Format)

After decryption, payload contains transport header + data. Min 8 bytes total.

#### Payload Header (Variable Size)

```
Byte 0:
  Bits 0-3: Version
  Bits 4-5: Message Type
    00 = DATA
    01 = PING (empty packet, needs ACK)
    10 = CLOSE
    11 = Reserved
  Bit 6: Offset size (0=24-bit, 1=48-bit)
  Bit 7: ACK present (0=no, 1=yes)

If ACK present (bit 7 = 1):
  Bytes 1-4:    Stream ID (32-bit)
  Bytes 5-7/10: Stream Offset (24 or 48-bit)
  Bytes 8-9/11-12: Length (16-bit)
  Byte 10/13:   Receive Window (8-bit, encoded)
  
Data section (always present):
  Bytes X+0-3:     Stream ID (32-bit)
  Bytes X+4-6/9:   Stream Offset (24 or 48-bit)
  Bytes X+7/10+:   Data (if length > 0)
```

**Window Encoding** (logarithmic compression):

```
Value  Capacity       Value  Capacity
0      0 B            50     16 KB
1      128 B          100    1 MB
2      256 B          150    96 MB
10     512 B          200    7 GB
18     1 KB           250    512 GB
                      255    ~896 GB (max)
```

Formula: `base * (1 + substep/8)` where `base = 2^(highBit)`, highBit derived from encoded value.

#### Message Types

**DATA**: Normal data transmission with optional ACK piggyback.

**PING**: Empty packet (length=0) that requires ACK. Not retransmitted if lost. Used for keepalive and RTT measurement.

**CLOSE**: Marks stream closure at current offset. Both sender and receiver can initiate.

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

#### Close Protocol

**Sender-Initiated**:
1. Sender calls `Close()` on stream
2. Marks `closeAtOffset` in send buffer (current queued data end)
3. Marks `closeAtOffset` in receive buffer (current receive offset)
4. Continues sending data up to `closeAtOffset`
5. Closes stream immediately when all data up to `closeAtOffset` is ACKed
6. No grace period on sender side

**Receiver-Initiated**:
1. Receiver calls `Close()` on stream
2. Marks `closeAtOffset` in receive buffer (current receive offset)
3. Marks `closeAtOffset` in send buffer (current queued data end)
4. Sender receives CLOSE message and marks its send buffer `closeAtOffset`
5. Receiver enters 30-second grace period starting when stream marked closed
6. After grace period expires, stream is cleaned up

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
- InitRcv: 87+ bytes (65 header + 6 SN + 16 MAC + ≥8 payload)
- InitCryptoSnd: 1400 bytes (includes padding)
- InitCryptoRcv: 63+ bytes (41 header + 6 SN + 16 MAC + ≥8 payload)
- Data: 31+ bytes (9 header + 6 SN + 16 MAC + ≥8 payload)

**Transport Layer Overhead** (variable):
- No ACK, 24-bit offset: 8 bytes
- No ACK, 48-bit offset: 11 bytes
- With ACK, 24-bit offset: 19 bytes
- With ACK, 48-bit offset: 25 bytes

**Total Minimum Overhead** (Data message with payload):
- Best case: 39 bytes (9 + 6 + 16 + 8 transport header)
- Typical: 39-47 bytes for data packets
- 1400-byte packet: ~2.8-3.4% overhead

## Implementation Details

### Data Structures

**LinkedMap**: O(1) insertion, deletion, lookup, and Next/Prev traversal. Used for connection and stream maps.

**SortedMap**: Skip list with O(log n) insertion/deletion, O(1) Get/Next/Prev when key exists. Used for receive buffer segments.

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