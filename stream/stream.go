package stream

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/zyguan/mysql-replay/stats"
	"go.uber.org/zap"
)

type MySQLPacket struct {
	Conn ConnID
	Time time.Time
	Dir  reassembly.TCPFlowDirection
	Len  int
	Seq  int
	Data []byte
}

type ConnID [2]gopacket.Flow

func (k ConnID) SrcAddr() string {
	return k[0].Src().String() + ":" + k[1].Src().String()
}

func (k ConnID) DstAddr() string {
	return k[0].Dst().String() + ":" + k[1].Dst().String()
}

func (k ConnID) String() string {
	return k.SrcAddr() + "->" + k.DstAddr()
}

func (k ConnID) Reverse() ConnID {
	return ConnID{k[0].Reverse(), k[1].Reverse()}
}

func (k ConnID) Hash() uint64 {
	h := fnvHash(k[0].Src().Raw(), k[1].Src().Raw()) + fnvHash(k[0].Dst().Raw(), k[1].Dst().Raw())
	h ^= uint64(k[0].EndpointType())
	h *= fnvPrime
	h ^= uint64(k[1].EndpointType())
	h *= fnvPrime
	return h
}

func (k ConnID) HashStr() string {
	buf := [8]byte{}
	binary.LittleEndian.PutUint64(buf[:], k.Hash())
	return hex.EncodeToString(buf[:])
}

func (k ConnID) Logger(name string) *zap.Logger {
	logger := zap.L().With(zap.String("conn", k.HashStr()+":"+k.SrcAddr()))
	if len(name) > 0 {
		logger = logger.Named(name)
	}
	return logger
}

type FactoryOptions struct {
	ConnCacheSize uint
	Synchronized  bool
	ForceStart    bool
}

func NewFactoryFromPacketHandler(factory func(ConnID) MySQLPacketHandler, opts FactoryOptions) reassembly.StreamFactory {
	if factory == nil {
		factory = defaultHandlerFactory
	}
	return &mysqlStreamFactory{new: factory, opts: opts}
}

var _ reassembly.StreamFactory = &mysqlStreamFactory{}

type mysqlStreamFactory struct {
	new  func(key ConnID) MySQLPacketHandler
	opts FactoryOptions
}

func (f *mysqlStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	conn := ConnID{netFlow, tcpFlow}
	log := conn.Logger("mysql-stream")
	h, ch, done := f.new(conn), make(chan MySQLPacket, f.opts.ConnCacheSize), make(chan struct{})
	if !f.opts.Synchronized {
		go func() {
			defer close(done)
			for pkt := range ch {
				h.OnPacket(pkt)
			}
		}()
	}
	stats.Add(stats.Streams, 1)
	return &mysqlStream{
		conn: conn,
		log:  log,
		ch:   ch,
		done: done,
		h:    h,
		opts: f.opts,
	}
}

var _ reassembly.Stream = &mysqlStream{}

type mysqlStream struct {
	conn ConnID

	log *zap.Logger
	buf *bytes.Buffer
	pkt *MySQLPacket

	ch   chan MySQLPacket
	done chan struct{}

	h    MySQLPacketHandler
	opts FactoryOptions
}

func (s *mysqlStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if !s.h.Accept(ci, dir, tcp) {
		return false
	}
	if s.opts.ForceStart {
		*start = true
	}
	return true
}

func (s *mysqlStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	if ac == nil {
		s.log.Info("skip nil assembler context")
		return
	}
	length, _ := sg.Lengths()
	if length == 0 {
		return
	}

	data := sg.Fetch(length)
	dir, _, _, _ := sg.Info()

	if s.buf == nil {
		buf := bytes.NewBuffer(data)
		seq := lookupPacketSeq(buf)
		if seq != 0 {
			s.log.Info("drop init packet with non-zero seq", zap.String("data", hex.EncodeToString(data)))
			return
		}
		s.buf = buf
	} else {
		s.buf.Write(data)
	}

	for s.buf.Len() > 0 {
		pkt := s.pkt
		if pkt == nil {
			pkt = &MySQLPacket{
				Conn: s.conn,
				Time: ac.GetCaptureInfo().Timestamp,
				Dir:  dir,
				Len:  lookupPacketLen(s.buf),
				Seq:  lookupPacketSeq(s.buf),
			}
		}
		if pkt.Seq == -1 || s.buf.Len() < pkt.Len+4 {
			s.log.Debug("wait for more packet data", zap.String("dir", dir.String()))
			if s.pkt == nil && pkt.Seq >= 0 {
				s.pkt = pkt
			}
			return
		}
		pkt.Data = make([]byte, pkt.Len)
		copy(pkt.Data, s.buf.Next(pkt.Len + 4)[4:])
		stats.Add(stats.Packets, 1)
		if s.opts.Synchronized {
			s.h.OnPacket(*pkt)
		} else {
			s.ch <- *pkt
		}
		s.pkt = nil
	}
}

func (s *mysqlStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	close(s.ch)
	if !s.opts.Synchronized {
		<-s.done
	}
	s.h.OnClose()
	stats.Add(stats.Streams, -1)
	return false
}

func lookupPacketLen(buf *bytes.Buffer) int {
	if buf.Len() < 3 {
		return -1
	}
	bs := buf.Bytes()[:3]
	return int(uint32(bs[0]) | uint32(bs[1])<<8 | uint32(bs[2])<<16)
}

func lookupPacketSeq(buf *bytes.Buffer) int {
	if buf.Len() < 4 {
		return -1
	}
	return int(buf.Bytes()[3])
}

const (
	fnvBasis = 14695981039346656037
	fnvPrime = 1099511628211
)

func fnvHash(chunks ...[]byte) (h uint64) {
	h = fnvBasis
	for _, chunk := range chunks {
		for i := 0; i < len(chunk); i++ {
			h ^= uint64(chunk[i])
			h *= fnvPrime
		}
	}
	return
}
