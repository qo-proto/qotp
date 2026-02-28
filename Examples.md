# QOTP Examples

Progressive examples from simple to advanced, demonstrating all public API functions.

## Example 1: Minimal Echo Server

The simplest possible server - echoes back whatever it receives.

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

## Example 2: Minimal Client

Connect to a server and send a message.

```go
package main

import (
    "context"
    "fmt"
    "io"
    "log"
    "time"

    "your/path/qotp"
)

func main() {
    listener, err := qotp.Listen()
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    // Connect to server (in-band key exchange, 1-RTT)
    conn, err := listener.DialString("127.0.0.1:8888")
    if err != nil {
        log.Fatal(err)
    }

    // Get stream 0
    stream := conn.Stream(0)

    // Send data
    stream.Write([]byte("Hello, QOTP!"))

    // Run loop to receive response
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    listener.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
        if s == nil {
            return nil
        }

        data, err := s.Read()
        if err == io.EOF {
            return nil
        }
        if err != nil {
            return err
        }

        if len(data) > 0 {
            fmt.Println("Received:", string(data))
            cancel() // Done
        }
        return nil
    })
}
```

## Example 3: Fixed Listen Address

Bind to a specific address and port.

```go
listener, err := qotp.Listen(
    qotp.WithListenAddr("0.0.0.0:8888"),
)
```

## Example 4: Deterministic Identity Key

Use a seed to generate a reproducible identity key. Useful for:
- Reconnecting with the same identity
- Out-of-band key exchange (0-RTT)

```go
// From raw bytes
var seed [32]byte
copy(seed[:], someBytes)
listener, err := qotp.Listen(qotp.WithSeed(seed))

// From hex string
listener, err := qotp.Listen(
    qotp.WithSeedHex("0x1234567890abcdef..."),
)

// From any string (hashed to 32 bytes)
listener, err := qotp.Listen(
    qotp.WithSeedString("my-secret-passphrase"),
)
```

## Example 5: 0-RTT Connection (Out-of-band Keys)

If you know the server's public key in advance, you can send data immediately without waiting for handshake.

```go
// Server: use deterministic key so clients can know it
serverListener, _ := qotp.Listen(
    qotp.WithListenAddr("0.0.0.0:8888"),
    qotp.WithSeedString("server-secret"),
)
// Server's public key can be shared out-of-band

// Client: connect with server's public key
clientListener, _ := qotp.Listen()

// Using hex-encoded public key
conn, err := clientListener.DialStringWithCryptoString(
    "127.0.0.1:8888",
    "0xaabbccdd...", // Server's public identity key
)

// Or using parsed public key
import "crypto/ecdh"
pubKey, _ := ecdh.X25519().NewPublicKey(pubKeyBytes)
conn, err := clientListener.DialStringWithCrypto("127.0.0.1:8888", pubKey)

// Can send data immediately (0-RTT)
stream := conn.Stream(0)
stream.Write([]byte("instant message"))
```

## Example 6: Multiple Streams

A single connection can multiplex multiple independent streams.

```go
conn, _ := listener.DialString("127.0.0.1:8888")

// Create multiple streams
stream0 := conn.Stream(0) // Control channel
stream1 := conn.Stream(1) // Data channel
stream2 := conn.Stream(2) // Another channel

// Each stream is independent
stream0.Write([]byte("control message"))
stream1.Write([]byte("data payload"))
stream2.Write([]byte("parallel data"))

// Close streams independently
stream1.Close() // Only closes stream 1
```

## Example 7: Stream Lifecycle

Understanding stream states and graceful close.

```go
stream := conn.Stream(0)

// Check if stream is usable
if stream.IsOpen() {
    stream.Write([]byte("data"))
}

// Initiate close (sends FIN)
stream.Close()

// After Close():
stream.IsCloseRequested() // true - Close() was called
stream.IsOpen()           // false
stream.Write([]byte("x")) // returns io.EOF

// Stream fully closed when both directions done:
stream.SndClosed() // true when our FIN is ACKed
stream.RcvClosed() // true when we received peer's FIN and read all data
stream.IsClosed()  // true when both SndClosed && RcvClosed
```

## Example 8: Graceful Shutdown

Wait for all streams to complete before closing.

```go
ctx, cancel := context.WithCancel(context.Background())

// Signal shutdown (e.g., from signal handler)
go func() {
    <-shutdownChan
    cancel()
}()

// Run until context cancelled
listener.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
    // ... handle streams
    return nil
})

// After Loop returns, wait for active streams
for listener.HasActiveStreams() {
    // Keep flushing to send pending ACKs
    listener.Flush(uint64(time.Now().UnixNano()))
    time.Sleep(10 * time.Millisecond)
}

listener.Close()
```

## Example 9: RTT Measurement with Ping

Send a ping to measure round-trip time.

```go
stream := conn.Stream(0)

// Queue a ping packet
stream.Ping()

// Ping will be sent on next Flush() and RTT measured when ACK arrives
// RTT is used internally for congestion control
```

## Example 10: Custom Max Payload

Adjust max UDP payload size for your network. Default is `interfaceMTU - 48` (typically 1452 for Ethernet).

```go
listener, err := qotp.Listen(
    qotp.WithMaxPayload(1200), // Smaller payload for tunnels/VPNs
)
```

Connections start at a conservative 1232 bytes and negotiate up to `min(local, remote)` maxPayload during handshake via `pktMtuUpdate`.

To re-detect the interface MTU at runtime (e.g., after switching from WiFi to Ethernet):

```go
listener.RefreshMaxPayload()
```

## Example 11: Wireshark Debugging

Log session keys for packet inspection.

```go
keyLog, _ := os.Create("keys.log")
defer keyLog.Close()

listener, err := qotp.Listen(
    qotp.WithKeyLogWriter(keyLog),
)

// Keys are logged in NSS key log format
// Use with Wireshark's "Pre-Master-Secret log filename" setting
```

## Example 12: Low-Level Control (Listen + Flush)

For advanced use cases, you can call Listen and Flush separately.

```go
listener, _ := qotp.Listen(qotp.WithListenAddr("0.0.0.0:8888"))

for {
    now := uint64(time.Now().UnixNano())
    
    // Receive one packet (with 100ms timeout)
    stream, err := listener.Listen(100_000_000, now)
    if err != nil {
        log.Println("error:", err)
        continue
    }
    
    if stream != nil {
        data, _ := stream.Read()
        if len(data) > 0 {
            stream.Write([]byte("response"))
        }
    }
    
    // Send pending data, get next wake time
    nextWakeNano := listener.Flush(uint64(time.Now().UnixNano()))
    
    // Could sleep until nextWakeNano for efficiency
    _ = nextWakeNano
}
```

## Example 13: Connection Info

Get identifiers for logging/debugging.

```go
stream := conn.Stream(5)

fmt.Printf("Connection ID: %d\n", stream.ConnID())
fmt.Printf("Stream ID: %d\n", stream.StreamID())
```

## Example 14: Handling Partial Writes

Write may return less than requested if buffer is full.

```go
data := make([]byte, 10_000_000) // 10MB

written := 0
for written < len(data) {
    n, err := stream.Write(data[written:])
    if err == io.EOF {
        log.Println("stream closed")
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    written += n
    
    if n == 0 {
        // Buffer full, need to flush
        time.Sleep(10 * time.Millisecond)
    }
}
```

## Example 15: Check Connection Activity

```go
// Check if any connection has active streams
if listener.HasActiveStreams() {
    log.Println("Still processing...")
}

// Check specific connection
if conn.HasActiveStreams() {
    log.Println("Connection still active")
}
```

---

## API Summary

### Listener Creation

| Function | Description |
|----------|-------------|
| `Listen(options...)` | Create a new listener |
| `WithListenAddr(addr)` | Bind to specific address |
| `WithMaxPayload(maxPayload)` | Set max UDP payload (default: interfaceMTU - 48) |
| `WithSeed(seed)` | Deterministic key from bytes |
| `WithSeedHex(hex)` | Deterministic key from hex |
| `WithSeedString(s)` | Deterministic key from string |
| `WithPrvKeyId(key)` | Use specific private key |
| `WithKeyLogWriter(w)` | Log keys for Wireshark |
| `WithNetworkConn(conn)` | Custom network (for testing) |

### Listener Methods

| Method | Description |
|--------|-------------|
| `Close()` | Close listener and all connections |
| `Loop(ctx, callback)` | Run event loop (recommended) |
| `Listen(timeout, now)` | Receive one packet (low-level) |
| `Flush(now)` | Send pending data (low-level) |
| `HasActiveStreams()` | Check for active streams |
| `RefreshMaxPayload()` | Re-detect interface MTU and recompute maxPayload |
| `Dial(addr)` | Connect with `netip.AddrPort` |
| `DialString(addr)` | Connect with string address |
| `DialWithCrypto(addr, pubKey)` | Connect (0-RTT) with `netip.AddrPort` |
| `DialStringWithCrypto(addr, pubKey)` | Connect (0-RTT) with string |
| `DialStringWithCryptoString(addr, pubKeyHex)` | Connect (0-RTT) with hex key |

### Connection Methods

Connection is returned by `Dial*` methods. The type is unexported (`*conn`) but these methods are available:

| Method | Description |
|--------|-------------|
| `Stream(id)` | Get or create stream |
| `HasActiveStreams()` | Check for active streams |

### Stream Methods

| Method | Description |
|--------|-------------|
| `Read()` | Read available data |
| `Write(data)` | Queue data for sending |
| `Close()` | Initiate graceful close |
| `Ping()` | Send ping for RTT measurement |
| `IsClosed()` | Both directions closed |
| `IsCloseRequested()` | Close() was called |
| `IsOpen()` | Not closing and not closed |
| `SndClosed()` | Send direction closed |
| `RcvClosed()` | Receive direction closed |
| `StreamID()` | Get stream ID |
| `ConnID()` | Get connection ID |
| `NotifyDataAvailable()` | Interrupt blocking read (internal) |

---

## Functions to Consider Hiding

The following are currently exported but should probably be internal (unexported):

### Definitely Internal

| Type/Function | Reason |
|--------------|--------|
| `SendBuffer`, `ReceiveBuffer`, `RcvBuffer` | Internal buffer implementation |
| `LinkedMap` | Internal data structure |
| `Measurements` | Internal BBR/RTT tracking |
| `PutUint16`, `PutUint24`, `Uint16`, etc. | Internal encoding helpers |
| `InsertStatus`, `AckStatus`, `RcvInsertStatus` | Internal status types |
| `Message` | Internal crypto message type |
| `NewSendBuffer`, `NewReceiveBuffer` | Internal constructors |
| `NewMeasurements` | Internal constructor |

### Maybe Internal

| Type/Function | Reason |
|--------------|--------|
| `NetworkConn`, `UDPNetworkConn` | Useful for testing, but could be internal |
| `WithNetworkConn` | Testing hook |
| `WithPrvKeyId` | Advanced use, `WithSeed*` covers most cases |
| `DecryptPcap` | Debugging tool, could be separate package |
| `Listen`, `Flush` on Listener | Low-level, `Loop` is preferred |
| `NotifyDataAvailable` on Stream | Internal signaling |

### Keep Exported

| Type/Function | Reason |
|--------------|--------|
| `Listener` | Main entry point |
| `Stream` | User-facing stream type |
| `Listen()` | Constructor |
| `With*` options (except internal ones) | Configuration |
| All `Dial*` methods | Connection establishment |
| `Loop`, `Close`, `HasActiveStreams` | Core API |
| Stream's `Read`, `Write`, `Close`, state checks | Core stream API |
| `Ping`, `StreamID`, `ConnID` | Useful utilities |

### Missing API (Consider Adding)

| Method | Description |
|--------|-------------|
| `Listener.PublicKey()` | Get identity public key for sharing (needed for 0-RTT) |
| `Listener.LocalAddr()` | Get listen address |

### Recommended Cleanup

To clean up the API, rename these to lowercase (unexport):

```go
// encoding.go
putUint16, putUint24, putUint32, putUint48, putUint64
uint16, uint24, uint32, uint48, uint64  // (rename to avoid conflict)

// snd.go, rcv.go
sendBuffer, receiveBuffer, rcvBuffer
insertStatus, ackStatus, rcvInsertStatus

// linkedmap.go
linkedMap

// measurement.go
measurements

// crypto.go
message

// net.go (maybe keep for testing)
// networkConn, udpNetworkConn

// loop.go
// Consider keeping Listen/Flush for advanced users
```