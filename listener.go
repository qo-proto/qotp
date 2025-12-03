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
	"sync"
	"time"
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

		seed, err := decodeHex(seedStrHex)
		if len(seed) != 32 {
			return errors.New("seed must be exactly 32 bytes")
		}
		if err != nil {
			return err
		}
		copy(o.seed[:], seed)
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
		lOpts.mtu = 1400 //default MTU
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
		mu:           sync.Mutex{},
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
	slog.Debug("ListenerClose", gId())
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	for _, conn := range l.connMap.items {
		conn.value.Close()
	}

	err := l.localConn.TimeoutReadNow()
	if err != nil {
		return err
	}
	return l.localConn.Close()
}

func (l *Listener) Listen(timeoutNano uint64, nowNano uint64) (s *Stream, err error) {
	data := make([]byte, l.mtu)
	n, remoteAddr, err := l.localConn.ReadFromUDPAddrPort(data, timeoutNano, nowNano)

	if err != nil {
		var netErr net.Error
		ok := errors.As(err, &netErr)

		if ok && netErr.Timeout() {
			return nil, nil // Timeout is normal, return no dataToSend/error
		} else {
			slog.Error("   Listen/Error", slog.Any("error", err))
			return nil, err
		}
	}
	if n == 0 {
		slog.Debug("   Listen/NoData")
		return nil, nil
	}

	slog.Debug("   Listen/Data", gId(), l.debug(), slog.Any("len(data)", n), slog.Uint64("now:ms", nowNano/msNano))

	conn, payload, msgType, err := l.decode(data[:n], remoteAddr)
	if err != nil {
		return nil, err
	}

	if nowNano > conn.lastReadTimeNano {
		conn.lastReadTimeNano = nowNano
	}

	var p *PayloadHeader
	if len(payload) == 0 && msgType == InitSnd { //InitSnd is the only message without any payload
		p = &PayloadHeader{}
		data = []byte{}
	} else {
		p, data, err = DecodePayload(payload)
		if err != nil {
			slog.Info("error in decoding payload from new connection", slog.Any("error", err))
			return nil, err
		}
	}

	s, err = conn.decode(p, data, n, nowNano)
	if err != nil {
		return nil, err
	}

	//Set state
	if !conn.isHandshakeDoneOnRcv {
		if conn.isSenderOnInit {
			if msgType == InitRcv || msgType == InitCryptoRcv {
				conn.isHandshakeDoneOnRcv = true
			}
		} else {
			if msgType == Data {
				conn.isHandshakeDoneOnRcv = true
			}
		}
	}

	return s, nil
}

// Flush sends pending data for all connections using round-robin
func (l *Listener) Flush(nowNano uint64) (minPacing uint64) {

	minPacing = MinDeadLine
	if l.connMap.Size() == 0 {
		//if we do not have at least one connection, exit
		return minPacing
	}

	closeConn := []*Conn{}
	closeStream := map[*Conn]uint32{}

	iter := NestedIterator(l.connMap, func(conn *Conn) *LinkedMap[uint32, *Stream] {
		return conn.streams
	}, l.currentConnID, l.currentStreamID)

	for conn, stream := range iter {
		dataSent, pacingNano, err := conn.Flush(stream, nowNano)
		if err != nil {
			slog.Info("closing connection, err", conn.debug(), slog.Any("err", err))
			closeConn = append(closeConn, conn)
			break
		}

		if stream.closedAtNano != 0 {
			if conn.isSenderOnInit {
				// stream closed on sender, mark for cleaning up, do not clean up yet, otherwise the iterator will become
				// much more complex
				closeStream[conn] = stream.streamID
				continue
			} else {
				// stream closed on receiver, wait for 30sec timeout before cleanup
				if stream.closedAtNano+ReadDeadLine > nowNano {
					closeStream[conn] = stream.streamID
					continue
				}
			}
		}

		if dataSent > 0 {
			// data sent, returning early
			minPacing = 0
			l.currentConnID = &conn.connId
			l.currentStreamID = &stream.streamID
			break
		}

		//no data sent, check if we reached the timeout for the activity
		if conn.lastReadTimeNano != 0 && nowNano > conn.lastReadTimeNano+ReadDeadLine {
			slog.Info("close connection, timeout", conn.debug(), slog.Uint64("now", nowNano),
				slog.Uint64("last", conn.lastReadTimeNano))
			closeConn = append(closeConn, conn)
			break
		}

		if pacingNano < minPacing {
			minPacing = pacingNano
		}
	}

	for _, closeConn := range closeConn {
		closeConn.cleanupConn()
	}

	for conn, stream := range closeStream {
		conn.cleanupStream(stream)
	}
	l.currentConnID = nil
	l.currentStreamID = nil
	return minPacing
}

func (l *Listener) newConn(
	connId uint64,
	remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEdRcv *ecdh.PublicKey,
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
		pubKeyEpRcv:        pubKeyEdRcv,
		mu:                 sync.Mutex{},
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

func (l *Listener) Loop(callback func(s *Stream) (bool, error)) {
	waitNextNano := MinDeadLine
	for {
		s, err := l.Listen(waitNextNano, uint64(time.Now().UnixNano()))
		if err != nil {
			slog.Error("Error in loop listen", slog.Any("error", err))
			break
		}
		// callback in any case, s may be null, but this gives the user
		// the control to cancel the Loop every MinDeadLine
		cont, err := callback(s)
		if err != nil {
			slog.Error("Error in loop callback", slog.Any("error", err))
			break
		}
		waitNextNano = l.Flush(uint64(time.Now().UnixNano()))

		if !cont {
			break
		}
	}
}

func (l *Listener) debug() slog.Attr {
	if l.localConn == nil {
		return slog.String("net", "n/a")
	}
	return slog.String("net", l.localConn.LocalAddrString())
}

func (l *Listener) ForceClose(c *Conn) {
	c.cleanupConn()
}

// logKey writes the session key to the key log in a format Wireshark can understand.
// The format is `QOTP_SHARED_SECRET <connId_hex> <secret_hex>`.
func logKey(w io.Writer, connId uint64, secret []byte, secretId []byte) {
	line := fmt.Sprintf("QOTP_SHARED_SECRET %x %x\n", connId, secret)
	_, err := w.Write([]byte(line))
	if err != nil {
		slog.Error("Failed to write to key log", "error", err)
	}
	line = fmt.Sprintf("QOTP_SHARED_SECRET_ID %x %x\n", connId, secretId)
	_, err = w.Write([]byte(line))
	if err != nil {
		slog.Error("Failed to write to key log", "error", err)
	}
}

func (l *Listener) DialString(remoteAddrString string) (*Conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	return l.Dial(remoteAddr)
}

func (l *Listener) DialWithCryptoString(remoteAddrString string, pubKeyIdRcvHex string) (*Conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	pubKeyIdRcv, err := decodeHexPubKey(pubKeyIdRcvHex)
	if err != nil {
		return nil, err
	}

	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}

func (l *Listener) DialWithCrypto(remoteAddr netip.AddrPort, pubKeyIdRcv *ecdh.PublicKey) (*Conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, pubKeyIdRcv, nil, true, true)
}

func (l *Listener) Dial(remoteAddr netip.AddrPort) (*Conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, nil, nil, true, false)
}
