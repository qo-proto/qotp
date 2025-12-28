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
	"strings"

	"net"
	"net/netip"
	"sync"
)

type Listener struct {
	// this is the port we are listening to
	localConn       NetworkConn
	prvKeyId        *ecdh.PrivateKey          //never nil
	connMap         *LinkedMap[uint64, *Conn] // here we store the connection to remote peers, we can have up to
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
		connMap:      NewLinkedMap[uint64, *Conn](),
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", lOpts.localConn.LocalAddrString()),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.prvKeyId.PublicKey().Bytes()[:3])+"…"))

	return l, nil
}

func (l *Listener) PubKey() *ecdh.PublicKey {
	return l.prvKeyId.PublicKey()
}

func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	for _, conn := range l.connMap.Iterator(nil) {
		conn.Close()
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
	withCrypto bool) (*Conn, error) {

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.connMap.Contains(connId) {
		slog.Warn("conn already exists", slog.Any("connId", connId))
		return nil, errors.New("conn already exists")
	}

	conn := &Conn{
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

func (l *Listener) decode(encData []byte, rAddr netip.AddrPort) (
	conn *Conn, userData []byte, msgType CryptoMsgType, err error) {
	// Read the header byte and connId
	if len(encData) < MinPacketSize {
		return nil, nil, 0, fmt.Errorf("header needs to be at least %v bytes", MinPacketSize)
	}

	header := encData[0]
	version := header & 0x1F // Extract bits 0-4 (mask 0001 1111)
	if version != CryptoVersion {
		return nil, nil, 0, errors.New("unsupported version")
	}
	msgType = CryptoMsgType(header >> 5)

	connId := Uint64(encData[HeaderSize : ConnIdSize+HeaderSize])

	switch msgType {
	case InitSnd:
		// Decode S0 message
		pubKeyIdSnd, pubKeyEpSnd, err := decryptInitSnd(encData, l.mtu)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
		}
		conn, exists := l.connMap.Get(connId)
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		var prvKeyEpRcv *ecdh.PrivateKey
		if !exists {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(connId, rAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, false)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
		}
		conn.sharedSecret = sharedSecret
		return conn, []byte{}, InitSnd, nil
	case InitRcv:
		connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])
		conn, exists := l.connMap.Get(connId)
		if !exists {
			return nil, nil, 0, errors.New("connection not found for InitRcv")
		}

		// Decode R0 message
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := decryptInitRcv(
			encData,
			conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitRcv: %w", err)
		}

		conn.pubKeyIdRcv = pubKeyIdRcv
		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		return conn, message.PayloadRaw, InitRcv, nil
	case InitCryptoSnd:
		// Decode crypto S0 message
		pubKeyIdSnd, pubKeyEpSnd, message, err := decryptInitCryptoSnd(
			encData, l.prvKeyId, l.mtu)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitWithCryptoS0: %w", err)
		}
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		conn, exists := l.connMap.Get(connId)

		var prvKeyEpRcv *ecdh.PrivateKey
		if !exists {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(connId, rAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, true)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

		conn.sharedSecret = sharedSecret
		return conn, message.PayloadRaw, InitCryptoSnd, nil
	case InitCryptoRcv:
		connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])
		conn, exists := l.connMap.Get(connId)
		if !exists {
			return nil, nil, 0, errors.New("connection not found for InitWithCryptoR0")
		}

		// Decode crypto R0 message
		sharedSecret, pubKeyEpRcv, message, err := decryptInitCryptoRcv(encData, conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
		}

		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		return conn, message.PayloadRaw, InitCryptoRcv, nil
	case Data:
		connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])
		conn, exists := l.connMap.Get(connId)
		if !exists {
			return nil, nil, 0, errors.New("connection not found for DataMessage")
		}

		// Decode Data message
		message, err := decryptData(encData, conn.isSenderOnInit, conn.epochCryptoRcv, conn.sharedSecret)
		if err != nil {
			return nil, nil, 0, err
		}

		//we decoded conn.epochCrypto + 1, that means we can safely move forward with the epoch
		if message.currentEpochCrypt > conn.epochCryptoRcv {
			conn.epochCryptoRcv = message.currentEpochCrypt
		}

		return conn, message.PayloadRaw, Data, nil
	default:
		return nil, nil, 0, fmt.Errorf("unknown message type: %v", msgType)
	}
}
