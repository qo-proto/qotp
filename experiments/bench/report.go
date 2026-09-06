package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/qo-proto/qotp"
	"github.com/qo-proto/qotp/experiments/internal/bench"
)

// The responder's report is sent length-prefixed so the reader knows when it
// has the whole thing: a stream gives no message boundaries.
const reportLenPrefix = 4

func encodeReport(r bench.ServerReport) ([]byte, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	out := make([]byte, reportLenPrefix+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	copy(out[reportLenPrefix:], body)
	return out, nil
}

// fetchServerReport opens a short qotp connection, asks for the responder's
// measurements and reads the reply.
func fetchServerReport(addr string) (*bench.ServerReport, error) {
	return fetchServerReportTimeout(addr, 15*time.Second)
}

func fetchServerReportTimeout(addr string, timeout time.Duration) (*bench.ServerReport, error) {
	ln, err := qotp.Listen(qotp.WithListenAddr("0.0.0.0:0"))
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	conn, err := ln.DialString(addr)
	if err != nil {
		return nil, err
	}
	stream := conn.Stream(0)
	if stream == nil {
		return nil, errors.New("stream 0 unavailable")
	}

	req := bench.EncodeHeader(bench.Report, 0)
	var sent int
	var buf []byte
	var want int

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	loopErr := ln.Loop(ctx, func(_ context.Context, _ *qotp.Stream) error {
		if sent < len(req) {
			n, err := stream.Write(req[sent:])
			if err != nil {
				return err
			}
			sent += n
		}
		if d, err := stream.Read(); err == nil && len(d) > 0 {
			buf = append(buf, d...)
		}
		if want == 0 && len(buf) >= reportLenPrefix {
			want = reportLenPrefix + int(binary.LittleEndian.Uint32(buf))
		}
		if want > 0 && len(buf) >= want {
			return errDone
		}
		return nil
	})
	if loopErr != nil && !errors.Is(loopErr, errDone) {
		return nil, loopErr
	}
	if want == 0 || len(buf) < want {
		// Distinguish "nothing came back at all" from "the responder answered
		// but the report did not finish": the first points at the network or
		// a responder that is not listening, the second does not.
		if stream.BytesDelivered() == 0 {
			return nil, errors.New("no response at all: nothing this side sent was acknowledged")
		}
		return nil, errors.New("responder answered but sent no report")
	}

	var r bench.ServerReport
	if err := json.Unmarshal(buf[reportLenPrefix:want], &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// =============================================================================
// JSON output
// =============================================================================

type jsonMeasurement struct {
	Run     int     `json:"run"`
	Mode    string  `json:"mode"`
	Dir     string  `json:"dir"`
	Proto   string  `json:"proto"`
	Mbps    float64 `json:"mbps"`
	Bytes   uint64  `json:"bytes"`
	Seconds float64 `json:"seconds"`
	Cores   float64 `json:"cores_busy"`
	Error   string  `json:"error,omitempty"`
}

type jsonSample struct {
	Phase    string  `json:"phase"`
	Run      int     `json:"run"`
	Proto    string  `json:"proto"`
	TSeconds float64 `json:"t_seconds"`
	CumBytes uint64  `json:"cum_bytes"`
}

type jsonOut struct {
	Config struct {
		Addr     string `json:"addr"`
		Port     int    `json:"port"`
		SizeMB   int    `json:"size_mb"`
		Runs     int    `json:"runs"`
		Duration string `json:"duration,omitempty"`
	} `json:"config"`
	Client struct {
		NumCPU int `json:"num_cpu"`
	} `json:"client"`
	Server       *bench.ServerReport `json:"server,omitempty"`
	Measurements []jsonMeasurement   `json:"measurements"`
	Samples      []jsonSample        `json:"samples"`
}

func writeJSON(cfg config, all []outcome, samples []sample, srv *bench.ServerReport) error {
	var out jsonOut
	out.Config.Addr = cfg.addr
	out.Config.Port = cfg.port
	out.Config.SizeMB = cfg.sizeMB
	out.Config.Runs = cfg.runs
	if cfg.duration > 0 {
		out.Config.Duration = cfg.duration.String()
	}
	out.Client.NumCPU = bench.NumCPU()
	out.Server = srv

	for _, o := range all {
		m := jsonMeasurement{
			Run: o.run, Mode: o.mode, Dir: o.dir.String(), Proto: o.proto,
			Mbps: o.mbps(), Bytes: o.bytes, Seconds: o.dur.Seconds(), Cores: o.cores,
		}
		if o.err != nil {
			m.Error = o.err.Error()
		}
		out.Measurements = append(out.Measurements, m)
	}
	for _, s := range samples {
		out.Samples = append(out.Samples, jsonSample{s.phase, s.run, s.proto, s.t.Seconds(), s.bytes})
	}

	f, err := os.Create(cfg.jsonPath)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
