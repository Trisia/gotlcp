// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlcp

import (
	"golang.org/x/crypto/cryptobyte"
)

// sessionState contains the information that is serialized into a session
// ticket in order to later resume a connection.
type sessionState struct {
	vers         uint16
	cipherSuite  uint16
	createdAt    uint64
	masterSecret []byte // opaque master_secret<1..2^16-1>;
	// struct { opaque certificate<1..2^24-1> } Certificate;
	certificates [][]byte // Certificate certificate_list<0..2^24-1>;

	// usedOldKey is true if the ticket from which this session came from
	// was encrypted with an older key and thus should be refreshed.
	usedOldKey bool
}

func (m *sessionState) marshal() []byte {
	var b cryptobyte.Builder
	b.AddUint16(m.vers)
	b.AddUint16(m.cipherSuite)
	addUint64(&b, m.createdAt)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.masterSecret)
	})
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, cert := range m.certificates {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(cert)
			})
		}
	})
	return b.BytesOrPanic()
}

func (m *sessionState) unmarshal(data []byte) bool {
	*m = sessionState{usedOldKey: m.usedOldKey}
	s := cryptobyte.String(data)
	if ok := s.ReadUint16(&m.vers) &&
		s.ReadUint16(&m.cipherSuite) &&
		readUint64(&s, &m.createdAt) &&
		readUint16LengthPrefixed(&s, &m.masterSecret) &&
		len(m.masterSecret) != 0; !ok {
		return false
	}
	var certList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certList) {
		return false
	}
	for !certList.Empty() {
		var cert []byte
		if !readUint24LengthPrefixed(&certList, &cert) {
			return false
		}
		m.certificates = append(m.certificates, cert)
	}
	return s.Empty()
}
