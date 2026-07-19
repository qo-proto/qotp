# QOTP - Quite OK Transport Protocol

⚠️ **Warning**: Protocol format is not final and may change.

A UDP-based transport protocol with an opinionated approach, similar to QUIC but focused on reasonable defaults over configurability. Goals: lower complexity, simplicity, security, and reasonable performance.

QOTP is P2P-friendly, supporting UDP hole punching, multi-homing (packets from different source addresses), out-of-band key exchange, no TIME_WAIT state, and single socket for multiple connections.

## Example

The following [link](Examples.md) shows example usage. Here is the most basic example that echoes back whatever it receives.

```go
package main

import (
    "context"
    "io"
    "log"

    "your/path/qotp"
)

func main() {
    // Create listener on random port
    listener, err := qotp.Listen()
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    log.Println("Server started")

    // Run event loop
    ctx := context.Background()
    listener.Loop(ctx, func(ctx context.Context, stream *qotp.Stream) error {
        if stream == nil {
            return nil // No data yet
        }

        data, err := stream.Read()
        if err == io.EOF {
            return nil // Stream closed
        }
        if err != nil {
            return err
        }

        if len(data) > 0 {
            stream.Write(data) // Echo back
        }

        return nil
    })
}
```

## Key Design Choices

- **Single crypto suite**: curve25519/chacha20poly1305
- **Always encrypted**: No plaintext option
- **In-band key rotation**: Forward secrecy preserved via periodic ECDH rekeying
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
* Max Payload: `interfaceMTU - 48` (typically 1452 for Ethernet; configurable via `WithMaxPayload`)
  * Connections start at `conservativeMTU` (1232) and negotiate up via the MTU update flag
* Buffer capacity: 16MB send + 16MB receive (configurable constants)
* Crypto sequence space: 48-bit sequence number per key
  * Separate from transport layer stream offsets
  * Key rotation is initiated at 2^46 packets and must complete by 2^47; the sequence number then resets under the new key
  * Connection lifetime is unbounded via periodic rekeying (which also refreshes forward secrecy)
* Transport sequence space: 48-bit stream offsets per stream
  * Multiple independent streams per connection

## Protocol Specification

### Message Flow

**Flow 1: In-band Key Exchange (No Prior Keys)**

```
Sender → Receiver: InitSnd (unencrypted, maxPayload bytes min)
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
  - maxPayload bytes min with padding

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
- `101` (5): Unused
- `110` (6): Unused
- `111` (7): Unused

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

Max Payload             = interfaceMTU - 48 (typically 1452)
Conservative MTU        = 1232 (IPv6 min link MTU 1280 - 48)
Send Buffer Capacity    = 16 MB
Receive Buffer Capacity = 16 MB
```

### Message Structures

#### InitSnd (Type 000, Min: maxPayload bytes)

Unencrypted, no data payload. Padded to maxPayload bytes to prevent amplification attacks.

```
Byte 0:       Header (version=0, type=000)
Bytes 1-32:   Public Key Ephemeral Sender (X25519)
              First 8 bytes = Connection ID
Bytes 33-64:  Public Key Identity Sender (X25519)
Bytes 65+:    Padding to maxPayload bytes
```

**Connection ID**: First 64 bits of pubKeyEpSnd, used for the lifetime of the connection.

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

#### InitCryptoSnd (Type 010, Min: maxPayload bytes)

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
Total:        Padded to maxPayload bytes
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

QOTP uses deterministic double encryption for sequence numbers and payload. A comparison with QUIC shows that QUIC uses a different approach called "header protection" where it samples 16 bytes from the encrypted payload, runs it through AES-ECB (or ChaCha20), and XORs the result with the packet number and header bits. This is a custom construction designed specifically for QUIC.

Note: The author is not a cryptographer. QOTP's approach was chosen for simplicity and reliance on standard primitives rather than custom constructions.

**Encryption Process**:

1. **First Layer** (Payload):
   - Nonce: 12 bytes deterministic
     - Bytes 0-5: Zero
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
5. Try decryption with the current, previous, and next shared secrets (key rotation window)
6. Verify MAC on payload - any tampering fails authentication

**Sequence Number Exhaustion**:

- At 2^46 packets the sender initiates a key rotation (see Key Rotation)
- Rotation must complete before 2^47 packets; the sequence number then resets to 0 under the new key
- If rotation has not completed by 2^47, the connection closes with an error
- Nonces never repeat under one key: the direction bit separates the peers, rotation bounds the packet count

### Key Rotation

QOTP supports in-band key rotation to maintain forward secrecy over long-lived connections. Both peers can initiate rotation independently.

**Protocol Flags**:
- `flagKeyUpdate` (bit 5): Carries initiator's new ephemeral public key (32 bytes)
- `flagKeyUpdateAck` (bit 6): Carries responder's new ephemeral public key (32 bytes)

**Key State**:
Each direction maintains three key slots:
- `prev`: Previous key (for packets in transit during rotation)
- `cur`: Current active key
- `next`: Pending key (computed but not yet promoted)

**Rotation Flow**:
```
Initiator                          Responder
    |                                  |
    |  KEY_UPDATE (new pubKeyEp)       |
    |--------------------------------->|
    |                                  | Generate new prvKeyEp
    |                                  | Compute next secret
    |  KEY_UPDATE_ACK (new pubKeyEp)   |
    |<---------------------------------|
    | Compute next secret              |
    | Promote: prev=cur, cur=next      |
    |                                  |
```

**Decryption**: Receiver tries `cur`, then `prev`, then `next` secrets to handle packets in flight during rotation.

**Sending and Retransmission**: Key update flags are derived from connection
state at encode time — the pending KEY_UPDATE is attached to the next
outgoing packet (data, ACK, or a KU-only packet when idle), then re-attached
once per RTO until the KEY_UPDATE_ACK arrives; any single carrier packet may
be lost. After `maxRetry` unanswered re-sends the connection errors. A lost
KEY_UPDATE_ACK needs no timer: the peer's retransmitted KEY_UPDATE
re-triggers it. Duplicate KEY_UPDATE packets (same pubKey as current or
previous round) are ignored or re-ACKed without generating new keys.

### Transport Layer (Payload Format)

After decryption, payload contains transport header + data. Min 8 bytes total.

#### Payload Header Format

**Byte 0 (Header byte)** — one independent flag per field, in wire order:
```
Bit 0: hasAck          ACK block present
Bit 1: hasStream       streamId + streamOffset (+ userData) present
Bit 2: extend          48-bit offsets instead of 24-bit
Bit 3: needsReTx       sender retransmits until ACKed (0 = best-effort)
Bit 4: isClose         stream close (FIN)
Bit 5: isKeyUpdate     32-byte pubkey present (key rotation initiation)
Bit 6: isKeyUpdateAck  32-byte pubkey present (key rotation acknowledgment)
Bit 7: isMtuUpdate     16-bit max UDP payload present
```

Any flag combination is representable; overhead is computable directly from
the flag byte. `needsReTx=0` on a data packet tells the receiver the stream
is best-effort: gaps from lost packets will never be repaired and are skipped
after a reorder deadline (see Unreliable Streams).

**MTU Negotiation (`isMtuUpdate`):**
- Carries a 2-byte `maxPayload` value from the sender
- Included in init packets (InitCryptoSnd, InitRcv, InitCryptoRcv) and the first data packet after InitSnd handshake (InitSnd embeds it in the crypto header instead)
- Not combined with close/keyUpdate packets (sizing policy, not a wire constraint)
- Both peers exchange their `maxPayload`; connection MTU = `min(local, remote)`, floored at `conservativeMTU` (1232)
- On consecutive packet losses (`mtuFallbackThreshold` = 5), MTU falls back to `conservativeMTU`; restored on next successful ACK
- More than 3 fallback→restore cycles on a connection logs an MTU-flapping warning (likely MTU black hole)

**Stream header** (streamId + offset, signaled by `hasStream`) is included when:
- Any control flag is set (close, key update, MTU update), OR
- Has user data, OR
- No ACK (for minimum packet size)

**ACK-only packets** (`hasStream=0` with `hasAck`): omit stream header to save space; trailing bytes after the ACK block are rejected.

**PING packets** (`hasStream=1` with zero remaining bytes): used for keepalive/RTT measurement. Pings are best-effort: never retransmitted, dropped from tracking one RTO after sending.

#### Packet Structure

**With ACK + Stream Data:**
```
Byte 0:           Header
Bytes 1-4:        ACK Stream ID (32-bit) [if hasAck]
Bytes 5-7/10:     ACK Offset (24 or 48-bit) [if hasAck]
Bytes 8-9/11-12:  ACK Length (16-bit) [if hasAck]
Byte 10/13:       ACK Receive Window (8-bit, encoded) [if hasAck]
Bytes X-X+1:      MTU Value (16-bit) [if isMtuUpdate]
Bytes Y-Y+31:     Key Update Public Key (32 bytes) [if isKeyUpdate]
Bytes Z-Z+31:     Key Update Ack Public Key (32 bytes) [if isKeyUpdateAck]
Bytes A-A+3:      Stream ID (32-bit) [if hasStream]
Bytes A+4-A+6/9:  Stream Offset (24 or 48-bit) [if hasStream]
Bytes A+7/10+:    User Data
```

#### Receive Window Encoding

The 8-bit receive window field encodes buffer capacity from 0 to ~896GB using logarithmic encoding with 8 substeps per power of 2:

### Flow Control and Congestion

#### BBR Congestion Control

**State Machine**:

```
Startup → Normal, with a periodic probe cycle:
Normal → Probe (1 round) → Drain (1 round) → Normal
```

**Pacing Gains**:
- Startup: 277% (2.77x) - aggressive growth
- Normal: 100% (1.0x) - steady state
- Probe: 125% (1.25x) - probe for spare bandwidth (one round)
- Drain: 75% (0.75x) - drain the queue the probe built (one round)

**State Transitions**:

1. **Startup → Normal**: 3 consecutive packet-timed rounds without ≥25% bandwidth growth
2. **Normal → Probe**: Every 8 × RTT_min. A probe is one round at 1.25x pacing of normal data (no extra packets), immediately followed by one drain round at 0.75x, then back to 1.0x

**Measurements**:

```
SRTT   = (7/8) × SRTT + (1/8) × RTT_sample          (RFC 6298; feeds RTO)
RTTVAR = (3/4) × RTTVAR + (1/4) × |SRTT - RTT_sample|
BW_sample = delivered_bytes_during_flight / RTT_sample  (delivery rate)
```

**RTT_min filter**: time-windowed minimum with a 10-second TTL, kept as a
monotonic staircase of candidates (oldest & smallest first). Higher samples
during queue buildup never displace the minimum; when the minimum expires,
the best still-valid candidate takes over.

**BW_max filter**: windowed maximum over the best sample of each of the last
10 packet-timed rounds (not per-ACK). It rises immediately on a better sample
but can only fall at round boundaries when old maxima age out. App-limited
rounds produce low samples, which a max filter ignores automatically. The
8-round probe interval and 10-round retention align: each probe's discovery
survives until the next probe re-validates it.

**Rounds**: a round ends when all packets in flight at its start are ACKed
(tracked via `deliveredAtSend >= roundDeliveredTarget`).

**Pacing Calculation**:

```
pacing_interval = (packet_size × 1e9) / (BW_max × gain_percent / 100)
```

If no bandwidth estimate: use `SRTT / 10` or fallback to 10ms
(≈10 packets per RTT, comparable to TCP's initial window).

#### Retransmission (RTO)

```
RTO = SRTT + 4 × RTTVAR
RTO = clamp(RTO, 100ms, 2000ms)
Default RTO = 200ms (when no SRTT)

Backoff: wait before retransmit n (n = 0..4) = min(RTO × 2^n, 2000ms)
Max retransmit attempts: 5 (maxRetry), then the connection errors
```

**Example timing** (default RTO = 200ms):
- Original send: t=0 (wait 200ms)
- Retransmit 1: t=200ms (wait 400ms)
- Retransmit 2: t=600ms (wait 800ms)
- Retransmit 3: t=1400ms (wait 1600ms)
- Retransmit 4: t=3000ms (wait 2000ms, capped)
- Retransmit 5: t=5000ms
- Fail: max retry exceeded

Best-effort packets (unreliable data, pings) are never retransmitted: they
are dropped from in-flight tracking one plain RTO after sending (no backoff)
and counted as losses (data only).

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

QOTP implements a clean bidirectional close mechanism similar to TCP FIN:

**Close Initiation (calling Close())**:
1. Marks `closeAtOffset` in send buffer at current write position (queued data + pending)
2. Continues sending queued data normally
3. When all data up to `closeAtOffset` is sent, sends CLOSE packet (may contain final data)
4. `sndClosed` becomes true when all data including CLOSE is ACKed

**Receiving CLOSE**:
1. Receives CLOSE packet at offset X
2. Marks `closeAtOffset = X` in receive buffer
3. Continues reading until reaching close offset
4. `rcvClosed` becomes true when `nextInOrder >= closeAtOffset`

**Stream Cleanup**:
- Stream is fully closed when both `sndClosed` and `rcvClosed` are true
- Cleanup happens when closed AND no pending ACKs for that stream

**Key Properties**:
- Both directions close independently (half-close supported)
- CLOSE packets must be ACKed like regular data
- CLOSE can be combined with data (final data packet includes CLOSE flag)
- Empty CLOSE packets allowed when no data pending
- `Write()` returns `io.EOF` after `Close()` is called
- `Read()` returns `io.EOF` after receive direction is closed

**Example Flow**:
```
A writes 100 bytes → calls Close()
  A.closeAtOffset = 100
  A sends DATA[0-100] with CLOSE flag

B receives CLOSE at offset 100
  B.closeAtOffset = 100
  B sends ACK for [0-100]
  B reads data, when nextInOrder reaches 100: B.rcvClosed = true

A receives ACK for [0-100]
  No in-flight data, sent up to closeAtOffset: A.sndClosed = true

B calls Close()
  B.closeAtOffset = 50 (whatever B's position is)
  B sends CLOSE
  
A receives CLOSE at offset 50
  A.closeAtOffset = 50
  A reads to offset 50: A.rcvClosed = true

When both sides have sndClosed && rcvClosed: stream cleanup
```

### Unreliable (Best-Effort) Streams

Streams are reliable by default. `SetReliable(false)` (call before the first
`Write`) switches a stream to best-effort delivery for real-time traffic
where retransmitting stale data is worse than dropping it.

**Sender side**:
- Data packets carry `needsReTx=0` and are never retransmitted
- Lost packets are dropped from in-flight tracking one RTO after sending
  (no backoff) and counted as losses
- Close (FIN) and key updates remain reliable even on unreliable streams
- ACKs are best-effort in both modes (sent once, never retransmitted)

**Receiver side (gap skipping)**:
- The first `needsReTx=0` data packet marks the stream unreliable (sticky)
- A head-of-line gap (lost packet) is skipped once it has been open longer
  than the reorder deadline: delivery advances to the next buffered segment,
  or to the close offset when the tail of the stream was lost
- Reorder deadline: 100ms default, per-stream override via
  `SetReorderDeadlineNano` — tune with `RTTNano()`/`RTTVarNano()`
  (e.g. srtt/2 or 4×rttvar)
- Data arriving for an already-skipped range is dropped and counted;
  poll `LatePackets()`/`LateBytes()` to observe it

**Consequences for the application**:
- The delivered byte stream may have lost ranges silently removed, so the
  application must do its own message framing
- RTT/bandwidth measurement works unchanged (delivered packets are ACKed)

### Connection Management

**Connection ID**: 
- First 64 bits of sender's ephemeral public key (`pubKeyEpSnd[0:8]`)
- Set once at connection creation, unchanged for connection lifetime
- Enables multi-homing (packets from different source addresses)

**Connection Timeout**: 
- 30 seconds of inactivity (no packets received)
- Automatic cleanup after timeout
- Configured via `ReadDeadLine` constant

**Single Socket**: 
- All connections share one UDP socket
- No TIME_WAIT state
- Scales to many short-lived connections

### Buffer Management

**Send Buffer** (`SendBuffer`):
- Capacity: 16 MB (configurable constant `sndBufferCapacity`)
- Tracks: queued data, in-flight data, ACKed data
- Per-stream accounting
- `queuedData`: data waiting to be sent (not yet transmitted)
- `inFlight`: sent but not ACKed (LinkedMap keyed by offset+length)
- Retransmission: oldest unACKed packet on RTO

**Receive Buffer** (`ReceiveBuffer`):
- Capacity: 16 MB (configurable constant `rcvBufferCapacity`)
- Handles: out-of-order delivery, overlapping segments
- Per-stream segments stored in LinkedMap (sorted by offset)
- Deduplication: checks against `nextInOrder`
- Overlap handling: overlapping bytes from an honest peer are identical; mismatches are logged and resolved to one copy
- Tracks finished streams to reject data for cleaned-up streams

**Packet Key Encoding** (64-bit):
```
Bits 0-15:  Length (16-bit)
Bits 16-63: Offset (48-bit)
```

Enables O(1) in-flight packet tracking and ACK processing.

## Overhead Analysis

**Crypto Layer Overhead**:
- InitSnd: maxPayload bytes (no data, padding)
- InitRcv: 103+ bytes (73 header + 6 SN + 16 MAC + ≥8 payload)
- InitCryptoSnd: maxPayload bytes (includes padding)
- InitCryptoRcv: 63+ bytes (41 header + 6 SN + 16 MAC + ≥8 payload)
- Data: 39+ bytes (9 header + 6 SN + 16 MAC + ≥8 payload)

**Transport Layer Overhead** (variable):
- No ACK, 24-bit offset: 8 bytes
- No ACK, 48-bit offset: 11 bytes
- With ACK, 24-bit offset: 18 bytes
- With ACK, 48-bit offset: 24 bytes
- MTU update flag adds 2 bytes (included in init and first data packet)

**Total Minimum Overhead** (Data message with payload):
- Best case: 39 bytes (9 + 6 + 16 + 8 transport header)
- Typical: 39-47 bytes for data packets
- 1452-byte packet: ~2.7-3.2% overhead

## Implementation Details

### Data Structures

**LinkedMap**: O(1) insertion, deletion, lookup, and Next/Prev traversal. Used for:
- Connection map (connId → conn)
- Stream map per connection (streamID → Stream)
- In-flight packets (packetKey → sendPacket)
- Receive segments (offset → data)

### Thread Safety

All buffer operations protected by mutexes:
- `SendBuffer.mu`: Protects send buffer operations
- `ReceiveBuffer.mu`: Protects receive buffer operations
- `conn.mu`: Protects connection state
- `Listener.mu`: Protects listener state
- `Stream.mu`: Protects stream read/write

### Error Handling

**Crypto Errors**:
- Authentication failures logged and dropped silently
- Malformed packets logged and dropped
- Key rotation: tries current, previous, and next secrets during transition

**Buffer Full**:
- Send: `Write()` returns partial bytes written
- Receive: Packet dropped with `RcvInsertBufferFull`

**Connection Errors**:
- RTO exhausted (5 retransmit attempts): Connection closed with error
- 30-second inactivity: Connection closed
- Key rotation not completed before sequence overflow (2^47): Connection closed with error

## Usage Example

```go
// Server
listener, _ := qotp.Listen(qotp.WithListenAddr("127.0.0.1:8888"))
defer listener.Close()

ctx, cancel := context.WithCancel(context.Background())
defer cancel()

listener.Loop(ctx, func(ctx context.Context, stream *qotp.Stream) error {
    if stream == nil {
        return nil // No data yet, continue
    }
    
    data, err := stream.Read()
    if err == io.EOF {
        return nil // Stream closed
    }
    if err != nil {
        return err // Exit loop on error
    }
    
    if len(data) > 0 {
        stream.Write([]byte("response"))
        stream.Close()
    }
    return nil
})

// Client (in-band key exchange, 1-RTT)
listener, _ := qotp.Listen()
conn, _ := listener.DialString("127.0.0.1:8888")
stream := conn.Stream(0)
stream.Write([]byte("hello"))

// Client (out-of-band keys, 0-RTT)
pubKeyHex := "0x1234..." // Receiver's public key
conn, _ := listener.DialStringWithCryptoString("127.0.0.1:8888", pubKeyHex)
stream := conn.Stream(0)
stream.Write([]byte("hello"))
```

### Stream Methods

```go
// Read returns available in-order data.
// Returns io.EOF after FIN received and all data delivered.
// Returns nil data (not error) if no data available yet.
func (s *Stream) Read() ([]byte, error)

// Write queues data for transmission.
// Returns io.EOF if stream is closing/closed.
// May return partial write if buffer full.
func (s *Stream) Write(userData []byte) (int, error)

// Close initiates graceful close of send direction.
// Receive direction remains open until peer's FIN.
func (s *Stream) Close()

// IsClosed returns true when both directions fully closed.
func (s *Stream) IsClosed() bool

// IsCloseRequested returns true if Close() has been called.
func (s *Stream) IsCloseRequested() bool

// Ping queues a best-effort ping packet for RTT measurement.
func (s *Stream) Ping()

// SetReliable controls retransmission of lost data (default true).
// Set to false for real-time streams; call before the first Write.
func (s *Stream) SetReliable(reliable bool)

// SetReorderDeadlineNano sets how long an unreliable stream waits for
// out-of-order data before skipping a gap (default 100ms).
func (s *Stream) SetReorderDeadlineNano(deadlineNano uint64)

// RTTNano / RTTVarNano expose the smoothed RTT and jitter estimates.
func (s *Stream) RTTNano() uint64
func (s *Stream) RTTVarNano() uint64

// LatePackets / LateBytes count data that arrived after its range
// was already skipped as lost (unreliable streams).
func (s *Stream) LatePackets() uint64
func (s *Stream) LateBytes() uint64
```

### Listener Options

```go
// Address to listen on
qotp.WithListenAddr("127.0.0.1:8888")

// Custom max payload (default: interfaceMTU - 48, typically 1452)
qotp.WithMaxPayload(1200)

// Pre-configured identity key
qotp.WithPrvKeyId(privateKey)

// Derive key from seed
qotp.WithSeed([32]byte{...})
qotp.WithSeedHex("0x1234...")
qotp.WithSeedString("my-secret-seed")

// Custom network connection (for testing)
qotp.WithNetworkConn(conn)

// Key logging for Wireshark
qotp.WithKeyLogWriter(file)
```

## Contributing

Protocol is experimental. Contributions welcome but expect breaking changes.