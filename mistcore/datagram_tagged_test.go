package mistcore

import (
	"bytes"
	"testing"
)

func TestDatagramTaggedRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		atyp byte
		addr []byte
		port uint16
		data []byte
		tag  byte
	}{
		{"ipv4-tagged", ATypIPv4, []byte{127, 0, 0, 1}, 5353, []byte("hello"), 7},
		{"ipv4-tag0", ATypIPv4, []byte{127, 0, 0, 1}, 5353, []byte("hello"), 0},
		{"ipv6-tagged", ATypIPv6, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 443, []byte("x"), 255},
		{"domain-tagged", ATypDomain, []byte("example.com"), 53, []byte("dns?"), 42},
		{"empty-data-tagged", ATypIPv4, []byte{10, 0, 0, 1}, 9999, []byte{}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := EncodeDatagramTagged(c.atyp, c.addr, c.port, c.data, c.tag)
			if c.tag == 0 && !bytes.Equal(enc, EncodeDatagram(c.atyp, c.addr, c.port, c.data)) {
				t.Fatal("tag==0 encoding must be byte-identical to EncodeDatagram")
			}
			atyp, addr, port, data, tag, err := DecodeDatagramTagged(enc)
			if err != nil {
				t.Fatal(err)
			}
			if atyp != c.atyp || !bytes.Equal(addr, c.addr) || port != c.port ||
				!bytes.Equal(data, c.data) || tag != c.tag {
				t.Fatalf("roundtrip mismatch: got atyp=%d addr=%v port=%d data=%q tag=%d",
					atyp, addr, port, data, tag)
			}
			// Old decoder must see clean data and ignore any trailer.
			_, _, _, oldData, err := DecodeDatagram(enc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(oldData, c.data) {
				t.Fatalf("old DecodeDatagram data=%q want %q", oldData, c.data)
			}
		})
	}
}

func TestDatagramTaggedBadTrailerIgnored(t *testing.T) {
	base := EncodeDatagram(ATypIPv4, []byte{127, 0, 0, 1}, 5353, []byte("payload"))
	trailers := [][]byte{
		{0x4D},                // 1 byte
		{0x4D, 0x54},          // magic only, no tag
		{0x4D, 0x54, 9, 0x00}, // 4 bytes
		{0x4D, 0x55, 9},       // wrong magic second byte
		{0x00, 0x00, 9},       // wrong magic
		{0xFF},                // junk
	}
	for i, tr := range trailers {
		p := append(append([]byte{}, base...), tr...)
		_, _, _, data, tag, err := DecodeDatagramTagged(p)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if tag != 0 {
			t.Fatalf("case %d: tag=%d want 0", i, tag)
		}
		if !bytes.Equal(data, []byte("payload")) {
			t.Fatalf("case %d: data=%q", i, data)
		}
	}
	// No trailer at all -> tag 0.
	_, _, _, _, tag, err := DecodeDatagramTagged(base)
	if err != nil || tag != 0 {
		t.Fatalf("no-trailer: tag=%d err=%v", tag, err)
	}
	// Short / corrupt input still errors like the old decoder.
	if _, _, _, _, _, err := DecodeDatagramTagged(base[:3]); err == nil {
		t.Fatal("short input must error")
	}
}
