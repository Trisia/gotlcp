package tlcp

import (
	"sync"
	"testing"
	"time"
)

var once = &sync.Once{}

func BenchmarkHandshake(b *testing.B) {
	once.Do(func() {
		go func() {
			err := server(38443)
			if err != nil {
				panic(err)
			}
		}()
	})
	time.Sleep(300 * time.Millisecond)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := Dial("tcp", "127.0.0.1:38443", &Config{RootCAs: simplePool})
			if err != nil {
				b.Fatal(err)
			}
			err = conn.Handshake()
			if err != nil {
				_ = conn.Close()
				b.Fatal(err)
			}
			_ = conn.Close()
		}
	})
}
