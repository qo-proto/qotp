package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"strings"

	"net"
	"net/netip"
	"sync"
)

type Listener struct {
	// this is the port we are listening to
	localConn       NetworkConn
	prvKeyId        *ecdh.PrivateKey          //never nil
	connMap         *LinkedMap[uint64, *conn] // here we store the connection to remote peers, we can have up to
	currentConnID   *uint64
	currentStreamID *uint32
	closed          bool
	keyLogWriter    io.Writer
	mtu             int
	mu              sync.Mutex
}

type ListenOption struct {
	seed         *[32]byte
	prvKeyId     *ecdh.PrivateKey
	localConn    NetworkConn
	listenAddr   *net.UDPAddr
	mtu          int
	keyLogWriter io.Writer
}

type ListenFunc func(*ListenOption) error

func WithMtu(mtu int) ListenFunc {
	return func(o *ListenOption) error {
		if o.mtu != 0 {
			return errors.New("mtu already set")
		}
		o.mtu = mtu
		return nil
	}
}

// WithKeyLogWriter sets a writer for logging session keys in SSLKEYLOGFILE format.
func WithKeyLogWriter(w io.Writer) ListenFunc {
	return func(o *ListenOption) error {
		o.keyLogWriter = w
		return nil
	}
}

func WithSeed(seed [32]byte) ListenFunc {
	return func(o *ListenOption) error {
		if o.seed != nil {
			return errors.New("seed already set")
		}
		o.seed = &seed
		return nil
	}
}

func WithNetworkConn(localConn NetworkConn) ListenFunc {
	return func(o *ListenOption) error {
		o.localConn = localConn
		return nil
	}
}

func WithPrvKeyId(prvKeyId *ecdh.PrivateKey) ListenFunc {
	return func(o *ListenOption) error {
		if o.prvKeyId != nil {
			return errors.New("prvKeyId already set")
		}
		if prvKeyId == nil {
			return errors.New("prvKeyId not set")
		}

		o.prvKeyId = prvKeyId
		return nil
	}
}

func WithSeedStrHex(seedStrHex string) ListenFunc {
	return func(o *ListenOption) error {
		if o.seed != nil {
			return errors.New("seed already set")
		}

		seedStrHex = strings.TrimPrefix(seedStrHex, "0x")
		seed, err := hex.DecodeString(seedStrHex)
		if err != nil {
			return err
		}
		if len(seed) != 32 {
			return errors.New("seed must be exactly 32 bytes")
		}
		o.seed = (*[32]byte)(seed) // allocate and assign
		return nil
	}
}

func WithSeedStr(seedStr string) ListenFunc {
	return func(o *ListenOption) error {
		if o.seed != nil {
			return errors.New("seed already set")
		}

		hashSum := sha256.Sum256([]byte(seedStr))
		o.seed = &hashSum
		return nil
	}
}

func WithListenAddr(addr string) ListenFunc {
	return func(o *ListenOption) error {
		if o.listenAddr != nil {
			return errors.New("listenAddr already set")
		}

		listenAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		o.listenAddr = listenAddr
		return nil
	}
}

func fillListenOpts(options ...ListenFunc) (*ListenOption, error) {
	lOpts := &ListenOption{}

	for _, opt := range options {
		err := opt(lOpts)
		if err != nil {
			return nil, err
		}
	}

	if lOpts.mtu == 0 {
		lOpts.mtu = defaultMTU //default MTU
	}
	if lOpts.seed != nil {
		prvKeyId, err := ecdh.X25519().NewPrivateKey(lOpts.seed[:])
		if err != nil {
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.prvKeyId == nil {
		prvKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.localConn == nil {
		conn, err := net.ListenUDP("udp", lOpts.listenAddr)
		if err != nil {
			return nil, err
		}

		err = setDontFragment(conn)
		if err != nil {
			return nil, err
		}

		lOpts.localConn = NewUDPNetworkConn(conn)
	}

	return lOpts, nil
}

func Listen(options ...ListenFunc) (*Listener, error) {
	lOpts, err := fillListenOpts(options...)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		localConn:    lOpts.localConn,
		prvKeyId:     lOpts.prvKeyId,
		mtu:          lOpts.mtu,
		keyLogWriter: lOpts.keyLogWriter,
		connMap:      NewLinkedMap[uint64, *conn](),
	}

	slog.Info("Listen", slog.String("listenAddr", lOpts.localConn.LocalAddrString()))

	return l, nil
}

func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	for _, conn := range l.connMap.Iterator(nil) {
		conn.close()
	}

	err := l.localConn.TimeoutReadNow()
	if err != nil {
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

func (l *Listener) newConn(
	connId uint64,
	remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	isSender bool,
	withCrypto bool) (*conn, error) {

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.connMap.Contains(connId) {
		slog.Warn("conn already exists", slog.Any("connId", connId))
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
		snCrypto:           0,
		snd:                NewSendBuffer(sndBufferCapacity),
		rcv:                NewReceiveBuffer(rcvBufferCapacity),
		Measurements:       NewMeasurements(),
		rcvWndSize:         rcvBufferCapacity, //initially our capacity, correct value will be sent to us when we need it
	}

	// Derive and log the shared secret for decryption in Wireshark
	if l.keyLogWriter != nil {
		sharedSecret, err := conn.prvKeyEpSnd.ECDH(conn.pubKeyEpRcv)
		if err != nil {
			return nil, err
		}
		sharedSecretId, err := conn.prvKeyEpSnd.ECDH(conn.pubKeyIdRcv)
		if err != nil {
			return nil, err
		}
		logKey(l.keyLogWriter, conn.connId, sharedSecret, sharedSecretId)
	}

	l.connMap.Put(connId, conn)
	return conn, nil
}

func (l *Listener) cleanupConn(connId uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentConnID != nil && connId == *l.currentConnID {
		tmp, _, _ := l.connMap.Next(connId)
		l.currentConnID = &tmp
	}
	l.connMap.Remove(connId)
}
