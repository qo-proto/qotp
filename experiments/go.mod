// The benchmark harness is a separate module so that the quic-go comparison
// baseline (and its transitive deps) stay out of the qotp library's module
// graph. It always builds against the checkout it sits in, via the replace
// directive below.
module github.com/qo-proto/qotp/experiments

go 1.27

replace github.com/qo-proto/qotp => ../

require (
	github.com/qo-proto/qotp v0.0.0-00010101000000-000000000000
	github.com/quic-go/quic-go v0.62.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
