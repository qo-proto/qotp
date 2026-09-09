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
// Listener - the UDP socket and its connections
// =============================================================================

// socketBufferSize is what quic-go requests; the OS may cap it (Linux:
// net.core.rmem_max)
const socketBufferSize = 7 * 1024 * 1024

// The read buffer holds any datagram, so a peer whose maxPayload grew after
// RefreshMaxPayload cannot send one that truncates and fails its MAC
const maxUDPPayload = 65535

type Listener struct {
	localConn    NetworkConn
	prvKeyId     *ecdh.PrivateKey
	connMap      *sharedLinkedMap[uint64, *conn]
	keyLogWriter io.Writer
	maxPayload   int

	// Round-robin cursors for Flush
	currentConnID   *uint64
	currentStreamID *uint32

	readBuf []byte
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

	if o.prvKeyId == nil {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		o.prvKeyId = k
	}

	if o.localConn == nil {
		conn, err := net.ListenUDP("udp", o.listenAddr)
		if err != nil {
			return nil, err
		}
		if err := setDontFragment(conn); err != nil {
			return nil, err
		}
		// The default socket buffer (about 200KB on Linux) is a few ms of
		// headroom at high rates; a longer event-loop pause drops packets
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

// RefreshMaxPayload re-reads the interface MTU, e.g. after switching from
// WiFi to Ethernet; peers learn the new value on their next packet. Call it
// from the Loop callback: the event loop reads maxPayload without a lock.
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

func (l *Listener) getOrCreateConn(connId uint64, rAddr netip.AddrPort, pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey, isSender, withCrypto bool) (*conn, error) {
	if conn, exists := l.connMap.get(connId); exists {
		return conn, nil
	}
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return l.newConn(connId, rAddr, prvKeyEp, pubKeyIdRcv, pubKeyEpRcv, isSender, withCrypto)
}

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
		rcvKeys:    &rcvKeyState{pubKeyEp: pubKeyEpRcv},
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
	// The 0-RTT secret is known before anything is sent; the others are
	// logged where the handshake establishes them
	if withCrypto && isSender && pubKeyIdRcv != nil && l.keyLogWriter != nil {
		if ssId, err := prvKeyEpSnd.ECDH(pubKeyIdRcv); err == nil {
			l.logSecret("QOTP_SHARED_SECRET_ID", connId, ssId)
		}
	}
	return conn, nil
}

// logSecret writes a line of the key log DecryptWithSecrets reads
func (l *Listener) logSecret(label string, connId uint64, secret []byte) {
	if l.keyLogWriter != nil {
		fmt.Fprintf(l.keyLogWriter, "%s %x %x\n", label, connId, secret)
	}
}
