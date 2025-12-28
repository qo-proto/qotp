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
				StreamID:     1,
				StreamOffset: 100,
				Ack:          &Ack{streamID: 10, offset: 200, len: 10, rcvWnd: 1000},
			},
			data: []byte("test data"),
		},
		{
			// Type 01: DATA no ACK (ping with empty data)
			header: &payloadHeader{
				StreamID:     5,
				StreamOffset: 50,
			},
			data: []byte{},
		},
		{
			// Type 10: CLOSE with ACK
			header: &payloadHeader{
				IsClose:      true,
				StreamID:     10,
				StreamOffset: 1000,
				Ack:          &Ack{streamID: 20, offset: 500, len: 100, rcvWnd: 5000},
			},
			data: []byte("closing"),
		},
		{
			// Type 11: CLOSE no ACK
			header: &payloadHeader{
				IsClose:      true,
				StreamID:     15,
				StreamOffset: 200,
			},
			data: []byte{},
		},
		{
			// Type 00: regular ack (nil userData, no data header)
			header: &payloadHeader{
				Ack: &Ack{streamID: 30, offset: 300, len: 50, rcvWnd: 2000},
			},
			data: nil,
		},
		{
			// Max values
			header: &payloadHeader{
				StreamID:     math.MaxUint32,
				StreamOffset: math.MaxUint64,
			},
			data: []byte("max"),
		},
	}

	for _, p := range payloads {
		encoded, _ := EncodePayload(p.header, p.data)
		f.Add(encoded)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, payloadData, err := DecodePayload(data)
		if err != nil {
			t.Skip()
		}

		// Re-encode and decode
		reEncoded, _ := EncodePayload(decoded, payloadData)
		reDecoded, reDecodedData, err := DecodePayload(reEncoded)
		if err != nil {
			t.Fatal("Failed to decode our own encoded data:", err)
		}

		// Compare data
		if !bytes.Equal(payloadData, reDecodedData) {
			t.Fatalf("Data mismatch: original=%v, reDecoded=%v", payloadData, reDecodedData)
		}

		// Compare payload fields
		if decoded.IsClose != reDecoded.IsClose {
			t.Fatal("IsClose mismatch")
		}
		if decoded.StreamID != reDecoded.StreamID {
			t.Fatal("StreamID mismatch")
		}
		if decoded.StreamOffset != reDecoded.StreamOffset {
			t.Fatal("StreamOffset mismatch")
		}

		// Compare Ack
		if (decoded.Ack == nil) != (reDecoded.Ack == nil) {
			t.Fatal("Ack presence mismatch")
		}
		if decoded.Ack != nil {
			if decoded.Ack.streamID != reDecoded.Ack.streamID {
				t.Fatal("Ack.streamID mismatch")
			}
			if decoded.Ack.offset != reDecoded.Ack.offset {
				t.Fatal("Ack.offset mismatch")
			}
			if decoded.Ack.len != reDecoded.Ack.len {
				t.Fatal("Ack.len mismatch")
			}
			// rcvWnd has lossy encoding - verify both encode to same value
			enc1 := EncodeRcvWindow(decoded.Ack.rcvWnd)
			enc2 := EncodeRcvWindow(reDecoded.Ack.rcvWnd)
			if enc1 != enc2 {
				t.Fatalf("rcvWnd encodes differently: %d->%d vs %d->%d",
					decoded.Ack.rcvWnd, enc1, reDecoded.Ack.rcvWnd, enc2)
			}
		}
	})
}
