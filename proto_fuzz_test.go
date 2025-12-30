package qotp

import (
	"bytes"
	"math"
	"testing"
)

func FuzzPayload(f *testing.F) {
	// Add seed corpus
	payloads := []struct {
		header *payloadHeader
		data   []byte
	}{
		{
			// Type 00: DATA with ACK
			header: &payloadHeader{
				streamId:     1,
				streamOffset: 100,
				ack:          &ack{streamId: 10, offset: 200, len: 10, rcvWnd: 1000},
			},
			data: []byte("test data"),
		},
		{
			// Type 01: DATA no ACK (ping with empty data)
			header: &payloadHeader{
				streamId:     5,
				streamOffset: 50,
			},
			data: []byte{},
		},
		{
			// Type 10: CLOSE with ACK
			header: &payloadHeader{
				isClose:      true,
				streamId:     10,
				streamOffset: 1000,
				ack:          &ack{streamId: 20, offset: 500, len: 100, rcvWnd: 5000},
			},
			data: []byte("closing"),
		},
		{
			// Type 11: CLOSE no ACK
			header: &payloadHeader{
				isClose:      true,
				streamId:     15,
				streamOffset: 200,
			},
			data: []byte{},
		},
		{
			// Type 00: regular ack (nil userData, no data header)
			header: &payloadHeader{
				ack: &ack{streamId: 30, offset: 300, len: 50, rcvWnd: 2000},
			},
			data: nil,
		},
		{
			// Max values
			header: &payloadHeader{
				streamId:     math.MaxUint32,
				streamOffset: math.MaxUint64,
			},
			data: []byte("max"),
		},
	}

	for _, p := range payloads {
		encoded, _ := encodeProto(p.header, p.data)
		f.Add(encoded)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, payloadData, err := decodeProto(data)
		if err != nil {
			t.Skip()
		}

		// Re-encode and decode
		reEncoded, _ := encodeProto(decoded, payloadData)
		reDecoded, reDecodedData, err := decodeProto(reEncoded)
		if err != nil {
			t.Fatal("Failed to decode our own encoded data:", err)
		}

		// Compare data
		if !bytes.Equal(payloadData, reDecodedData) {
			t.Fatalf("Data mismatch: original=%v, reDecoded=%v", payloadData, reDecodedData)
		}

		// Compare payload fields
		if decoded.isClose != reDecoded.isClose {
			t.Fatal("IsClose mismatch")
		}
		if decoded.streamId != reDecoded.streamId {
			t.Fatal("StreamID mismatch")
		}
		if decoded.streamOffset != reDecoded.streamOffset {
			t.Fatal("StreamOffset mismatch")
		}

		// Compare Ack
		if (decoded.ack == nil) != (reDecoded.ack == nil) {
			t.Fatal("Ack presence mismatch")
		}
		if decoded.ack != nil {
			if decoded.ack.streamId != reDecoded.ack.streamId {
				t.Fatal("Ack.streamID mismatch")
			}
			if decoded.ack.offset != reDecoded.ack.offset {
				t.Fatal("Ack.offset mismatch")
			}
			if decoded.ack.len != reDecoded.ack.len {
				t.Fatal("Ack.len mismatch")
			}
			// rcvWnd has lossy encoding - verify both encode to same value
			enc1 := encodeRcvWindow(decoded.ack.rcvWnd)
			enc2 := encodeRcvWindow(reDecoded.ack.rcvWnd)
			if enc1 != enc2 {
				t.Fatalf("rcvWnd encodes differently: %d->%d vs %d->%d",
					decoded.ack.rcvWnd, enc1, reDecoded.ack.rcvWnd, enc2)
			}
		}
	})
}
