package scannode

import "crypto/x509"

// x509Certificate keeps the VerifyPeerCertificate signature in sink_tls.go
// readable without importing crypto/x509 there for a type we never construct.
type x509Certificate = x509.Certificate
