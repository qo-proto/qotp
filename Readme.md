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
- **Compact**: ~3k LoC source code (find . -maxdepth 1 -type f ! -name '*_test.go' -print0 | xargs -0 tokei)

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
  * Connections start at `conservativeMTU` (1232) and negotiate up via the `maxPayload` field carried in every packet
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

#### InitRcv (Type 001, Min: 105 bytes)

Encrypted with ECDH(prvKeyEpRcv, pubKeyEpSnd). Achieves perfect forward secrecy.

```
Byte 0:       Header (version=0, type=001)
Bytes 1-8:    Connection ID (from InitSnd)
Bytes 9-40:   Public Key Ephemeral Receiver (X25519)
Bytes 41-72:  Public Key Identity Receiver (X25519)
Bytes 73-78:  Encrypted Sequence Number (48-bit)
Bytes 79+:    Encrypted Payload (min 10 bytes)
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
Bytes X+:     Encrypted Payload (min 10 bytes)
Last 16:      MAC (Poly1305)
Total:        Padded to maxPayload bytes
```

#### InitCryptoRcv (Type 011, Min: 73 bytes)

Encrypted with ECDH(prvKeyEpRcv, pubKeyEpSnd). Achieves perfect forward secrecy.

```
Byte 0:       Header (version=0, type=011)
Bytes 1-8:    Connection ID (from InitCryptoSnd)
Bytes 9-40:   Public Key Ephemeral Receiver (X25519)
Bytes 41-46:  Encrypted Sequence Number (48-bit)
Bytes 47+:    Encrypted Payload (min 11 bytes)
Last 16:      MAC (Poly1305)
```

#### Data (Type 100, Min: 42 bytes)

All subsequent data messages after handshake.

```
Byte 0:       Header (version=0, type=100)
Bytes 1-8:    Connection ID
Bytes 9-14:   Encrypted Sequence Number (48-bit)
Bytes 15+:    Encrypted Payload (min 11 bytes)
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

After decryption, payload contains transport header + data. Min 10 bytes total.

#### Payload Header Format

**Byte 0 (Header byte)** — one independent flag per field:
```
Bit 0: hasAck          ACK block present
Bit 1: hasStream       streamId + streamOffset (+ userData) present
Bit 2: extend          48-bit offsets instead of 24-bit
Bit 3: isClose         stream close (FIN)
Bit 4: isKeyUpdate     32-byte pubkey present (key rotation initiation)
Bit 5: isKeyUpdateAck  32-byte pubkey present (key rotation acknowledgment)
Bits 6-7: reserved
```

Any flag combination is representable; overhead is computable directly from
the flag byte.

**Stream reliability** is not a flag. It travels in the **high bit of the wire
`streamId`** (set = best-effort), which caps usable stream IDs at 2^31-1. A
best-effort stream never retransmits, so a once-announced flag could be lost
and strand the receiver waiting on gaps that never fill; carried in the ID, the
marker is on every packet of the stream by construction. The receiver's marking
is sticky: gaps from lost packets are skipped after a reorder deadline (see
Unreliable Streams). Whether the sender retransmits an individual packet — it
always does for FIN and key updates, even on a best-effort stream — is local
state and never appears on the wire.

**MTU Negotiation (`maxPayload`):**
- A 2-byte field in the fixed header of every packet, immediately after the flags byte (InitSnd embeds it in the crypto header instead, and carries no transport header)
- Unconditional because MTU is a path property that can change at any time (interface change, and later connection migration or a second path). Costs 2 bytes per packet and removes all "already announced" state; a change reaches the peer on the next packet
- Both peers exchange their `maxPayload`; connection MTU = `min(local, remote)`, floored at `conservativeMTU` (1232)

**Path MTU.** `maxPayload` says what the peer's *interface* accepts; it says
nothing about the path in between, which may black-hole larger packets while
DF is set and the ICMP that would say so is filtered. The MTU therefore moves
only on evidence, never on loss:

- A connection starts at `conservativeMTU` and is raised to the negotiated size on the peer's word, unconfirmed
- An ACK for a **first transmission** confirms that size traverses the path. Once confirmed, loss is congestion and never lowers the MTU
- A packet within `mtuProbeLastAttempts` (2) of giving up is retransmitted at `conservativeMTU`. The retransmit *is* the probe — no separate probe traffic
- If that probe is acknowledged while the working size was never confirmed, the path cannot carry it: downgrade to `conservativeMTU`, log once, and stay there for the life of the connection. Later `maxPayload` advertisements cannot undo it

Inferring an MTU problem from loss instead, as an earlier version did, made the
MTU oscillate many times a second on any lossy path and re-split in-flight data
on every change.

**Stream header** (streamId + offset, signaled by `hasStream`) is included when:
- Any control flag is set (close, key update), OR
- Has user data, OR
- No ACK (for minimum packet size)

**ACK-only packets** (`hasStream=0` with `hasAck`): omit stream header to save space; trailing bytes after the ACK block are rejected.

**PING packets** (`hasStream=1` with zero remaining bytes): used for keepalive/RTT measurement. Pings are best-effort: never retransmitted, dropped from tracking one RTO after sending.

#### Packet Structure

**With ACK + Stream Data:**
```
Byte 0:           Header (flags)
Bytes 1-2:        maxPayload (16-bit, always present)
Byte 3:           Receive Window (8-bit, encoded, always present)
Bytes 4-7:        ACK Stream ID (32-bit) [if hasAck]
Bytes 8-10/13:    ACK Offset (24 or 48-bit) [if hasAck]
Bytes 11-12/...:  ACK Length (16-bit) [if hasAck]
Bytes Y-Y+31:     Key Update Public Key (32 bytes) [if isKeyUpdate]
Bytes Z-Z+31:     Key Update Ack Public Key (32 bytes) [if isKeyUpdateAck]
Bytes A-A+3:      Stream ID (32-bit, high bit = best-effort) [if hasStream]
Bytes A+4-A+6/9:  Stream Offset (24 or 48-bit) [if hasStream]
Bytes A+7/10+:    User Data
```

#### Receive Window Encoding

The 8-bit receive window rides every packet, not just ACK-carrying ones: it
describes the whole connection's receive buffer, and a sender blocked by it has
nothing to acknowledge, so inside the ACK block it would be unreachable exactly
when it matters. It encodes buffer capacity from 0 to ~896GB using logarithmic
encoding with 8 substeps per power of 2:

### Flow Control and Congestion

**Stale windows are ignored.** Free space describes the instant a packet was
built, so a reordered older packet carries a smaller, obsolete value. The
sender applies a window only from the highest sequence number it has seen,
which costs no wire bytes — the sequence number is already on every packet. The
counter resets when the peer's key rotates, because its sequence number does.

**Blocked senders probe.** The window is only ever learned from a received
packet, and a peer with nothing to acknowledge sends none — so a sender that
went quiet when blocked would wait for a peer that is waiting for it. A blocked
sender therefore emits an empty packet until the window reopens, and a receiver
whose buffer drains well below what it last announced sends one unprompted.
That update may be lost, so it does not replace the probe.

The probe interval backs off like a retransmit, but the probe never gives up:
a peer refusing data is behaving correctly, so there is no failure to count. A
peer that has actually gone away is ended by the 30s read deadline instead —
the probe reports zero bytes sent, so it cannot hold the connection open.

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

**Karn's algorithm**: ACKs of retransmitted packets are never measured — they
are ambiguous (original or retransmit?), and a wrong sample would stick in
the extremal min/max filters below.

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
- Calculated as: `max(0, buffer_capacity - current_buffer_usage)` (usage can briefly exceed capacity, see below)
- Encoded logarithmically (8-bit → 896GB range)
- Sender respects: `data_in_flight + packet_size ≤ rcv_window`

**Pacing**: 
- Sender tracks `next_write_time`
- Waits until `now ≥ next_write_time` before sending
- Even ACK-only packets respect pacing (can send early if needed)

### Stream Management

Stream IDs are application-chosen and range from `0` to `2^31-1`; the high bit
of the wire ID is reserved for the best-effort marker, so `conn.Stream()`
returns `nil` for an ID outside that range.

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
- The high bit of the wire `streamId` is set on every packet of the stream;
  data packets are never retransmitted
- Lost packets are dropped from in-flight tracking one RTO after sending
  (no backoff) and counted as losses
- Close (FIN) and key updates remain reliable even on unreliable streams
- ACKs are best-effort in both modes (sent once, never retransmitted)

**Receiver side (gap skipping)**:
- Any packet with the marker bit set marks the stream unreliable (sticky).
  Because the marker rides the stream ID, losing a packet cannot leave the
  receiver treating a best-effort stream as reliable
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
- Unanswered handshake: init packets are re-sent with RTO backoff and the
  connection errors after `maxRetry` re-sends (~5s), same as data
  retransmits. 0-RTT inits carrying data use the regular retransmit path.

**Single Socket**: 
- All connections share one UDP socket
- No TIME_WAIT state
- Scales to many short-lived connections

### Buffer Management

**Send Buffer** (`sender`):
- Capacity: 16 MB (configurable constant `sndBufferCapacity`)
- Tracks: queued data, in-flight data, ACKed data
- Per-stream accounting
- `queuedData`: data waiting to be sent (not yet transmitted)
- `inFlight`: sent but not ACKed (LinkedMap keyed by offset+length)
- Retransmission: oldest unACKed reliable packet on RTO; best-effort packets are dropped instead

**Receive Buffer** (`receiver`):
- Capacity: 16 MB (configurable constant `rcvBufferCapacity`)
- Handles: out-of-order delivery, overlapping segments
- Per-stream segments stored in LinkedMap (sorted by offset)
- Deduplication: checks against `nextInOrder`
- Overlap handling: overlapping bytes from an honest peer are identical; mismatches are logged and resolved to one copy
- In-order data (fills the head-of-line gap) is accepted even when full — it is immediately drainable, so accepting it frees space; rejecting it would deadlock. Usage may briefly exceed capacity by one segment as a result.
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
- InitRcv: 106+ bytes (73 header + 6 SN + 16 MAC + ≥11 payload)
- InitCryptoSnd: maxPayload bytes (includes padding)
- InitCryptoRcv: 74+ bytes (41 header + 6 SN + 16 MAC + ≥11 payload)
- Data: 42+ bytes (9 header + 6 SN + 16 MAC + ≥11 payload)

**Transport Layer Overhead** (variable; every packet includes the 2-byte
`maxPayload` and 1-byte receive-window fields):
- No ACK, 24-bit offset: 11 bytes
- No ACK, 48-bit offset: 14 bytes
- With ACK, 24-bit offset: 20 bytes
- With ACK, 48-bit offset: 26 bytes
- ACK-only (no stream header), 24-bit offset: 13 bytes
- Each key-update pubkey adds 32 bytes

**Total Minimum Overhead** (Data message with payload):
- Best case: 42 bytes (9 + 6 + 16 + 11 transport header)
- Typical: 42-52 bytes for data packets
- 1452-byte packet: ~2.8-3.5% overhead

## Implementation Details

### Data Structures

**LinkedMap**: O(1) insertion, deletion, lookup, and Next/Prev traversal. Used for:
- Connection map (connId → conn)
- Stream map per connection (streamID → Stream)
- In-flight packets (packetKey → sendPacket)
- Receive segments (offset → data)

### Thread Safety

The design is a single event-loop goroutine: `Loop` calls `Flush` (send) then
`Listen` (receive) in sequence, so those two never overlap. User goroutines may
concurrently call `Stream` methods (`Read`/`Write`/`Ping`/`Close`) and
`Listener` methods; the boundary between them and the loop is guarded by
per-component locks:

- `sender.mu` / `receiver.mu`: send and receive buffers (shared: user
  `Write`/`Read` vs. the loop's send/receive)
- `linkedMap.mu`: the stream/connection maps
- `conn.mu`: the connection's stream map and receive-path processing, vs. user
  calls to `Stream()` / `HasActiveStreams()`
- `Listener.mu`: connection lifecycle
- `Stream.mu`: `Read`/`Write` serialization

The **send path (`Flush` → `flushStream`) runs without `conn.mu`** and mutates
connection-scalar state (measurements, `dataInFlight`, `phase`, sequence
number) — this is safe only because it shares the loop goroutine with the
receive path. Consequently the measurement getters (`RTTNano`, `RTTVarNano`)
are safe only when called from the `Loop` callback, which runs on that same
goroutine. The `LatePackets`/`LateBytes` counters, by contrast, are guarded by
`receiver.mu` and safe from any goroutine.

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
- Handshake unanswered after 5 init re-sends (~5s): Connection closed with error
- Key update unanswered after 5 re-sends: Connection closed with error
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
// Read them from the Loop callback: the send path updates them without a
// lock, so reading from another goroutine is a data race.
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