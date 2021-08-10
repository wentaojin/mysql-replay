package stream

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/zyguan/mysql-replay/event"
)

func NewFactoryFromEventHandler(factory func(ConnID) MySQLEventHandler, opts FactoryOptions) reassembly.StreamFactory {
	f := defaultHandlerFactory
	if factory != nil {
		f = func(conn ConnID) MySQLPacketHandler {
			return &eventHandler{
				fsm:  NewMySQLFSM(conn.Logger("mysql-stream")),
				conn: conn,
				impl: factory(conn),
			}
		}
	}
	return &mysqlStreamFactory{new: f, opts: opts}
}

type MySQLEventHandler interface {
	OnEvent(event event.MySQLEvent)
	OnClose()
}

type eventHandler struct {
	fsm  *MySQLFSM
	conn ConnID
	impl MySQLEventHandler
}

func (h *eventHandler) Accept(ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, tcp *layers.TCP) bool {
	return true
}

func (h *eventHandler) OnPacket(pkt MySQLPacket) {
	h.fsm.Handle(pkt)
	if !h.fsm.Ready() || !h.fsm.Changed() {
		return
	}
	e := event.MySQLEvent{Time: pkt.Time.UnixNano() / int64(time.Millisecond), Conn: h.conn.Hash()}
	switch h.fsm.State() {
	case StateComQuery:
		e.Type = event.EventQuery
		e.Query = h.fsm.Query()
	case StateComStmtExecute:
		stmt := h.fsm.Stmt()
		e.Type = event.EventStmtExecute
		e.StmtID = uint64(stmt.ID)
		e.Params = h.fsm.StmtParams()
	case StateComStmtPrepare1:
		stmt := h.fsm.Stmt()
		e.Type = event.EventStmtPrepare
		e.StmtID = uint64(stmt.ID)
		e.Query = stmt.Query
	case StateComStmtClose:
		stmt := h.fsm.Stmt()
		e.Type = event.EventStmtClose
		e.StmtID = uint64(stmt.ID)
	case StateHandshake1:
		e.Type = event.EventHandshake
		e.DB = h.fsm.Schema()
	case StateComQuit:
		e.Type = event.EventQuit
	default:
		return
	}
	h.impl.OnEvent(e)
}

func (h *eventHandler) OnClose() {
	h.impl.OnClose()
}
