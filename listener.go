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
	"sync"
)

// =============================================================================
// Listener - Manages UDP socket and connections
// =============================================================================

type Listener struct {
	localConn    NetworkConn
	prvKeyId     *ecdh.PrivateKey
	connMap      *LinkedMap[uint64, *conn]
	keyLogWriter io.Writer
	mtu          int

	// Round-robin state for Flush()
	currentConnID   *uint64
	currentStreamID *uint32

	mu sync.Mutex
}

// =============================================================================
// Functional options for Listen()
// =============================================================================

type ListenOption struct {
	prvKeyId     *ecdh.PrivateKey
	localConn    NetworkConn
	listenAddr   *net.UDPAddr
	mtu          int
	keyLogWriter io.Writer
}

type ListenFunc func(*ListenOption) error

func WithMtu(mtu int) ListenFunc {
	return func(o *ListenOption) error { o.mtu = mtu; return nil }
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
	o := &ListenOption{mtu: defaultMTU}
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
		o.localConn = NewUDPNetworkConn(conn)
	}

	l := &Listener{
		localConn:    o.localConn,
		prvKeyId:     o.prvKeyId,
		mtu:          o.mtu,
		keyLogWriter: o.keyLogWriter,
		connMap:      NewLinkedMap[uint64, *conn](),
	}
	slog.Info("Listen", slog.String("listenAddr", o.localConn.LocalAddrString()))
	return l, nil
}

// =============================================================================
// Public methods
// =============================================================================

func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, conn := range l.connMap.Iterator(nil) {
		conn.closeAllStreams()
	}
	if err := l.localConn.TimeoutReadNow(); err != nil {
		return err
	}
	return l.localConn.Close()
}

func (l *Listener) HasActiveStreams() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, conn := range l.connMap.Iterator(nil) {
		if conn.HasActiveStreams() || conn.rcv.HasPendingAcks() {
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
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.connMap.Contains(connId) {
		return nil, errors.New("conn already exists")
	}

	conn := &conn{
		connId:             connId,
		streams:            NewLinkedMap[uint32, *Stream](),
		remoteAddr:         remoteAddr,
		pubKeyIdRcv:        pubKeyIdRcv,
		prvKeyEpSnd:        prvKeyEpSnd,
		pubKeyEpRcv:        pubKeyEpRcv,
		listener:           l,
		isSenderOnInit:     isSender,
		isWithCryptoOnInit: withCrypto,
		snd:                NewSendBuffer(sndBufferCapacity),
		rcv:                NewReceiveBuffer(rcvBufferCapacity),
		Measurements:       NewMeasurements(),
		rcvWndSize:         rcvBufferCapacity,
	}

	// Log keys for Wireshark debugging if enabled
	if l.keyLogWriter != nil {
		if ss, err := conn.prvKeyEpSnd.ECDH(conn.pubKeyEpRcv); err == nil {
			if ssId, err := conn.prvKeyEpSnd.ECDH(conn.pubKeyIdRcv); err == nil {
				// =============================================================================
				// Wireshark/pcap support
				//
				// logKey: Writes session keys for Wireshark decryption (NSS key log format)
				// DecryptPcap: Standalone packet decryption for offline analysis
				// =============================================================================
				fmt.Fprintf(l.keyLogWriter, "QOTP_SHARED_SECRET %x %x\n", conn.connId, ss)
				fmt.Fprintf(l.keyLogWriter, "QOTP_SHARED_SECRET_ID %x %x\n", conn.connId, ssId)
			}
		}
	}

	l.connMap.Put(connId, conn)
	return conn, nil
}

func (l *Listener) cleanupConn(connId uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Advance round-robin pointer if we're removing current connection
	if l.currentConnID != nil && connId == *l.currentConnID {
		tmp, _, _ := l.connMap.Next(connId)
		l.currentConnID = &tmp
	}
	l.connMap.Remove(connId)
}
