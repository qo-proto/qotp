package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
)

// =============================================================================
// Listener - Manages UDP socket and connections
// =============================================================================

// socketBufferSize is the requested UDP send/receive buffer (same value
// quic-go uses); the OS may cap it lower (Linux: net.core.rmem_max).
const socketBufferSize = 7 * 1024 * 1024

// maxUDPPayload is the largest datagram UDP can carry. The read buffer is this
// size rather than maxPayload so that a later RefreshMaxPayload, which the peer
// learns of on the next packet, cannot leave the buffer too small for what it
// then sends: a truncated datagram fails its MAC and is simply lost.
const maxUDPPayload = 65535

type Listener struct {
	localConn    NetworkConn
	prvKeyId     *ecdh.PrivateKey
	connMap      *sharedLinkedMap[uint64, *conn]
	keyLogWriter io.Writer
	maxPayload   int

	// Round-robin state for Flush()
	currentConnID   *uint64
	currentStreamID *uint32

	readBuf []byte // reusable buffer for Listen()
}

// =============================================================================
// Functional options for Listen()
// =============================================================================

type ListenOption struct {
	prvKeyId     *ecdh.PrivateKey
	localConn    NetworkConn
	listenAddr   *net.UDPAddr
	maxPayload   int
	keyLogWriter io.Writer
}

type ListenFunc func(*ListenOption) error

func WithMaxPayload(maxPayload int) ListenFunc {
	return func(o *ListenOption) error { o.maxPayload = maxPayload; return nil }
}

func WithKeyLogWriter(w io.Writer) ListenFunc {
	return func(o *ListenOption) error { o.keyLogWriter = w; return nil }
}

func WithNetworkConn(c NetworkConn) ListenFunc {
	return func(o *ListenOption) error { o.localConn = c; return nil }
}

func WithPrvKeyId(k *ecdh.PrivateKey) ListenFunc {
	return func(o *ListenOption) error { o.prvKeyId = k; return nil }
}

func WithListenAddr(addr string) ListenFunc {
	return func(o *ListenOption) error {
		a, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}
		o.listenAddr = a
		return nil
	}
}

// Seed options - derive identity key from various inputs

func WithSeed(seed [32]byte) ListenFunc {
	return func(o *ListenOption) error {
		k, err := ecdh.X25519().NewPrivateKey(seed[:])
		if err != nil {
			return err
		}
		o.prvKeyId = k
		return nil
	}
}

func WithSeedHex(hexStr string) ListenFunc {
	return func(o *ListenOption) error {
		b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
		if err != nil {
			return err
		}
		if len(b) != 32 {
			return errors.New("seed must be 32 bytes")
		}
		return WithSeed([32]byte(b))(o)
	}
}

func WithSeedString(s string) ListenFunc {
	return func(o *ListenOption) error {
		return WithSeed(sha256.Sum256([]byte(s)))(o)
	}
}

// =============================================================================
// Constructor
// =============================================================================

func Listen(options ...ListenFunc) (*Listener, error) {
	o := &ListenOption{}
	for _, opt := range options {
		if err := opt(o); err != nil {
			return nil, err
		}
	}

	// Generate random identity key if not provided
	if o.prvKeyId == nil {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		o.prvKeyId = k
	}

	// Create UDP socket if not provided
	if o.localConn == nil {
		conn, err := net.ListenUDP("udp", o.listenAddr)
		if err != nil {
			return nil, err
		}
		if err := setDontFragment(conn); err != nil {
			return nil, err
		}
		// Large socket buffers: the default (~200KB on Linux) is only a
		// few ms of headroom at high rates — any event-loop pause longer
		// than that overflows the socket, dropping packets invisibly
		// before they reach us. The OS caps the request (Linux:
		// net.core.rmem_max/wmem_max); raise those limits for full
		// effect, as QUIC stacks recommend.
		if err := conn.SetReadBuffer(socketBufferSize); err != nil {
			slog.Info("could not request UDP read buffer", "size", socketBufferSize, "err", err)
		}
		if err := conn.SetWriteBuffer(socketBufferSize); err != nil {
			slog.Info("could not request UDP write buffer", "size", socketBufferSize, "err", err)
		}
		o.localConn = NewUDPNetworkConn(conn)
	}

	var interfaceMTU int
	if udpConn, ok := o.localConn.(*UDPNetworkConn); ok {
		interfaceMTU = getInterfaceMTU(udpConn.conn)
	} else {
		interfaceMTU = 1500
	}

	// Compute max payload from interface MTU
	maxPayload := o.maxPayload
	if maxPayload == 0 {
		maxPayload = interfaceMTU - ipOverhead
	}
	maxPayload = max(maxPayload, conservativeMTU)

	l := &Listener{
		localConn:    o.localConn,
		prvKeyId:     o.prvKeyId,
		maxPayload:   maxPayload,
		keyLogWriter: o.keyLogWriter,
		connMap:      newSharedLinkedMap[uint64, *conn](),
		readBuf:      make([]byte, maxUDPPayload),
	}
	slog.Info("Listen", slog.String("listenAddr", o.localConn.LocalAddrString()))
	return l, nil
}

// =============================================================================
// Public methods
// =============================================================================

func (l *Listener) Close() error {
	for _, conn := range l.connMap.iterator(nil) {
		conn.closeAllStreams()
	}
	if err := l.localConn.TimeoutReadNow(); err != nil {
		return err
	}
	return l.localConn.Close()
}

// RefreshMaxPayload re-reads the network interface MTU and recomputes
// maxPayload; the new value reaches every peer on its next packet. Call it when
// the interface changes (e.g. WiFi to Ethernet), and like RTTNano call it from
// the Loop callback: the event loop reads maxPayload without a lock.
func (l *Listener) RefreshMaxPayload() {
	if udpConn, ok := l.localConn.(*UDPNetworkConn); ok {
		l.maxPayload = max(getInterfaceMTU(udpConn.conn)-ipOverhead, conservativeMTU)
	}
}

func (l *Listener) HasActiveStreams() bool {
	for _, conn := range l.connMap.iterator(nil) {
		if conn.HasActiveStreams() || conn.rcv.hasPendingAcks() {
			return true
		}
	}
	return false
}

// =============================================================================
// Connection management (internal)
// =============================================================================

func (l *Listener) newConn(
	connId uint64,
	remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey,
	isSender, withCrypto bool,
) (*conn, error) {
	var initMsgType cryptoMsgType
	switch {
	case withCrypto && isSender:
		initMsgType = initCryptoSnd
	case withCrypto:
		initMsgType = initCryptoRcv
	case isSender:
		initMsgType = initSnd
	default:
		initMsgType = initRcv
	}

	conn := &conn{
		connId:     connId,
		streams:    newSharedLinkedMap[uint32, *Stream](),
		remoteAddr: remoteAddr,
		rcvKeys: &rcvKeyState{
			pubKeyEp: pubKeyEpRcv,
			keyState: keyState{
				prvKeyEp: prvKeyEpSnd,
			},
		},
		sndKeys: &keyState{
			prvKeyEp: prvKeyEpSnd,
		},
		pubKeyIdRcv:  pubKeyIdRcv,
		listener:     l,
		initMsgType:  initMsgType,
		snd:          newSendBuffer(sndBufferCapacity),
		rcv:          newReceiveBuffer(rcvBufferCapacity),
		measurements: newMeasurements(),
		rcvWndSize:   rcvBufferCapacity,
		mtu:          conservativeMTU,
	}

	if _, loaded := l.connMap.getOrPut(connId, conn); loaded {
		return nil, errors.New("conn already exists")
	}
	// A 0-RTT dialer knows the InitCryptoSnd secret before anything is sent;
	// every other secret is logged where the handshake establishes it.
	if withCrypto && isSender && pubKeyIdRcv != nil && l.keyLogWriter != nil {
		if ssId, err := prvKeyEpSnd.ECDH(pubKeyIdRcv); err == nil {
			l.logSecret("QOTP_SHARED_SECRET_ID", connId, ssId)
		}
	}
	return conn, nil
}

// cleanupConn removes connection state. A stale round-robin cursor pointing
// at the removed conn is fine: linkedMap.iterator falls back to the beginning.
func (l *Listener) cleanupConn(connId uint64) {
	l.connMap.remove(connId)
}

// logSecret writes one line of the key log read by DecryptWithSecrets.
func (l *Listener) logSecret(label string, connId uint64, secret []byte) {
	if l.keyLogWriter != nil {
		fmt.Fprintf(l.keyLogWriter, "%s %x %x\n", label, connId, secret)
	}
}
