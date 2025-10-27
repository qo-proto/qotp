package qotp

import (
	"bytes"
	"math"
	"testing"
)

func FuzzPayload(f *testing.F) {
	// Add seed corpus
	payloads := []*PayloadHeader{
		{
			MsgType:      MsgTypeData,
			StreamID:     1,
			StreamOffset: 100,
			Ack:          &Ack{streamID: 10, offset: 200, len: 10, rcvWnd: 1000},
		},
		{
			MsgType:      MsgTypePing,
			StreamID:     5,
			StreamOffset: 50,
		},
		{
			MsgType:      MsgTypeClose,
			StreamID:     10,
			StreamOffset: 1000,
			Ack:          &Ack{streamID: 20, offset: 500, len: 100, rcvWnd: 5000},
		},
		{
			MsgType:      MsgTypeData,
			StreamID:     math.MaxUint32,
			StreamOffset: math.MaxUint64,
		},
	}
	for _, p := range payloads {
		originalData := []byte("test data")
		encoded, _ := EncodePayload(p, originalData)
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
			t.Fatal("Data mismatch")
		}

		// Compare payload fields
		if decoded.MsgType != reDecoded.MsgType ||
			decoded.StreamID != reDecoded.StreamID ||
			decoded.StreamOffset != reDecoded.StreamOffset {
			t.Fatal("Payload fields mismatch")
		}

		// Compare Ack
		if (decoded.Ack == nil) != (reDecoded.Ack == nil) {
			t.Fatal("Ack presence mismatch")
		}
		if decoded.Ack != nil {
			if decoded.Ack.streamID != reDecoded.Ack.streamID ||
				decoded.Ack.offset != reDecoded.Ack.offset ||
				decoded.Ack.len != reDecoded.Ack.len {
				t.Fatal("Ack fields differ")
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