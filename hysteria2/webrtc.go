package hysteria2

import (
	"crypto/rand"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	wrHeaderLen = 12 // fake RTP header length
	wrSaltLen   = 8
)

const ObfsTypeWebrtc = "webrtc"

type WebrtcPacketConn struct {
	net.PacketConn
	password []byte
}

func NewWebrtcConn(conn net.PacketConn, password []byte) net.PacketConn {
	writer, isVectorised := bufio.CreateVectorisedPacketWriter(conn)
	if isVectorised {
		return &VectorisedWebrtcPacketConn{
			WebrtcPacketConn: WebrtcPacketConn{
				PacketConn: conn,
				password:   password,
			},
			writer: writer,
		}
	} else {
		return &WebrtcPacketConn{
			PacketConn: conn,
			password:   password,
		}
	}
}

func (w *WebrtcPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = w.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	if n <= wrHeaderLen+wrSaltLen {
		return
	}
	// Basic plausibility check: RTP version
	if (p[0] & 0xC0) != 0x80 {
		return
	}
	// Move payload to head of buffer
	payload := p[wrHeaderLen+wrSaltLen : n]
	copy(p, payload)
	return len(payload), addr, nil
}

func (w *WebrtcPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(wrHeaderLen + wrSaltLen + len(p))
	defer buffer.Release()

	// allocate header+salt with random bytes
	buffer.WriteRandom(wrHeaderLen + wrSaltLen)
	b := buffer.Bytes()
	// set RTP-like header fields
	b[0] = 0x80
	b[1] = 96
	if _, err := rand.Read(b[2:4]); err != nil {
		return 0, err
	}
	if _, err := rand.Read(b[4:8]); err != nil {
		return 0, err
	}
	if _, err := rand.Read(b[8:12]); err != nil {
		return 0, err
	}
	// salt is already random (b[wrHeaderLen:wrHeaderLen+wrSaltLen])

	// append payload
	common.Must1(buffer.Write(p))

	_, err = w.PacketConn.WriteTo(buffer.Bytes(), addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *WebrtcPacketConn) Upstream() any {
	return w.PacketConn
}

type VectorisedWebrtcPacketConn struct {
	WebrtcPacketConn
	writer N.VectorisedPacketWriter
}

func (w *VectorisedWebrtcPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	header := buf.NewSize(wrHeaderLen + wrSaltLen)
	header.WriteRandom(wrHeaderLen + wrSaltLen)
	hb := header.Bytes()
	hb[0] = 0x80
	hb[1] = 96
	if _, err := rand.Read(hb[2:4]); err != nil {
		header.Release()
		return 0, err
	}
	if _, err := rand.Read(hb[4:8]); err != nil {
		header.Release()
		return 0, err
	}
	if _, err := rand.Read(hb[8:12]); err != nil {
		header.Release()
		return 0, err
	}
	// write vectorised: header + payload
	err = w.writer.WriteVectorisedPacket([]*buf.Buffer{header, buf.As(p)}, M.SocksaddrFromNet(addr))
	if err != nil {
		header.Release()
		return 0, err
	}
	return len(p), nil
}

func (w *VectorisedWebrtcPacketConn) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	header := buf.NewSize(wrHeaderLen + wrSaltLen)
	defer header.Release()
	header.WriteRandom(wrHeaderLen + wrSaltLen)
	hb := header.Bytes()
	hb[0] = 0x80
	hb[1] = 96
	if _, err := rand.Read(hb[2:4]); err != nil {
		return err
	}
	if _, err := rand.Read(hb[4:8]); err != nil {
		return err
	}
	if _, err := rand.Read(hb[8:12]); err != nil {
		return err
	}
	return w.writer.WriteVectorisedPacket(append([]*buf.Buffer{header}, buffers...), destination)
}
