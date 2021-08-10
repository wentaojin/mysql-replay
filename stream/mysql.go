package stream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/google/gopacket/reassembly"
	"github.com/pingcap/errors"
	"go.uber.org/zap"
)

const (
	StateInit = iota
	StateUnknown
	StateComQuery
	StateComStmtExecute
	StateComStmtClose
	StateComStmtPrepare0
	StateComStmtPrepare1
	StateComQuit
	StateHandshake0
	StateHandshake1
)

func StateName(state int) string {
	switch state {
	case StateInit:
		return "Init"
	case StateUnknown:
		return "Unknown"
	case StateComQuery:
		return "ComQuery"
	case StateComStmtExecute:
		return "ComStmtExecute"
	case StateComStmtClose:
		return "ComStmtClose"
	case StateComStmtPrepare0:
		return "ComStmtPrepare0"
	case StateComStmtPrepare1:
		return "ComStmtPrepare1"
	case StateComQuit:
		return "ComQuit"
	case StateHandshake0:
		return "Handshake0"
	case StateHandshake1:
		return "Handshake1"
	default:
		return "Invalid"
	}
}

type Stmt struct {
	ID        uint32
	Query     string
	NumParams int

	types []byte
}

func NewMySQLFSM(log *zap.Logger) *MySQLFSM {
	return &MySQLFSM{
		log:     log,
		state:   StateInit,
		data:    new(bytes.Buffer),
		stmts:   map[uint32]Stmt{},
		params:  []interface{}{},
		packets: []MySQLPacket{},
	}
}

type MySQLFSM struct {
	log *zap.Logger

	// state info
	changed bool
	state   int
	query   string        // com_query
	stmt    Stmt          // com_stmt_prepare,com_stmt_execute,com_stmt_close
	params  []interface{} // com_stmt_execute

	// session info
	schema string          // handshake1
	stmts  map[uint32]Stmt // com_stmt_prepare,com_stmt_execute,com_stmt_close

	// current command
	data    *bytes.Buffer
	packets []MySQLPacket
	start   int
	count   int
}

func (fsm *MySQLFSM) State() int { return fsm.state }

func (fsm *MySQLFSM) Query() string { return fsm.query }

func (fsm *MySQLFSM) Stmt() Stmt { return fsm.stmt }

func (fsm *MySQLFSM) Stmts() []Stmt {
	stmts := make([]Stmt, 0, len(fsm.stmts))
	for _, stmt := range fsm.stmts {
		stmts = append(stmts, stmt)
	}
	return stmts
}

func (fsm *MySQLFSM) StmtParams() []interface{} { return fsm.params }

func (fsm *MySQLFSM) Schema() string { return fsm.schema }

func (fsm *MySQLFSM) Changed() bool { return fsm.changed }

func (fsm *MySQLFSM) Ready() bool {
	n := len(fsm.packets)
	return n > 0 && fsm.packets[n-1].Len < maxPacketSize
}

func (fsm *MySQLFSM) Handle(pkt MySQLPacket) {
	fsm.changed = false
	if fsm.state == StateComQuit {
		return
	}
	if pkt.Seq == 0 {
		fsm.set(StateInit, "recv packet with seq(0)")
		fsm.packets = fsm.packets[:0]
		fsm.packets = append(fsm.packets, pkt)
	} else if fsm.nextSeq() == pkt.Seq {
		fsm.packets = append(fsm.packets, pkt)
	} else {
		return
	}

	if !fsm.Ready() {
		return
	}

	if fsm.state == StateInit {
		fsm.handleInitPacket()
	} else if fsm.state == StateComStmtPrepare0 {
		fsm.handleComStmtPrepareResponse()
	} else if fsm.state == StateHandshake0 {
		fsm.handleHandshakeResponse()
	}
}

func (fsm *MySQLFSM) Packets() []MySQLPacket {
	if fsm.start+fsm.count > len(fsm.packets) {
		return nil
	}
	return fsm.packets[fsm.start : fsm.start+fsm.count]
}

func (fsm *MySQLFSM) nextSeq() int {
	n := len(fsm.packets)
	if n == 0 {
		return 0
	}
	return fsm.packets[n-1].Seq + 1
}

func (fsm *MySQLFSM) load(k int) bool {
	i, j := 0, 0
	for i < len(fsm.packets) {
		j = i
		for j < len(fsm.packets) && fsm.packets[j].Len == maxPacketSize {
			j += 1
		}
		if j == len(fsm.packets) {
			return false
		}
		if i == k {
			fsm.data.Reset()
			for k <= j {
				fsm.data.Write(fsm.packets[k].Data)
				k += 1
			}
			fsm.start, fsm.count = i, j-i+1
			return true
		}
		i = j + 1
	}
	return false
}

func (fsm *MySQLFSM) set(to int, msg ...string) {
	from := fsm.state
	fsm.state = to
	fsm.changed = from != to
	if !fsm.changed || fsm.log == nil || !fsm.log.Core().Enabled(zap.DebugLevel) {
		return
	}
	tmpl := "mysql fsm(%s->%s)"
	query := fsm.query
	if to != StateComQuery {
		query = fsm.stmt.Query
	}
	if n := len(query); n > 500 {
		query = query[:300] + "..." + query[n-196:]
	}
	switch to {
	case StateComQuery:
		tmpl += fmt.Sprintf("{query:%q}", query)
	case StateComStmtExecute:
		tmpl += fmt.Sprintf("{query:%q,id:%d,params:%v}", query, fsm.stmt.ID, fsm.params)
	case StateComStmtPrepare0:
		tmpl += fmt.Sprintf("{query:%q}", query)
	case StateComStmtPrepare1:
		tmpl += fmt.Sprintf("{query:%q,id:%d,num-params:%d}", query, fsm.stmt.ID, fsm.stmt.NumParams)
	case StateComStmtClose:
		tmpl += fmt.Sprintf("{query:%q,id:%d,num-params:%d}", query, fsm.stmt.ID, fsm.stmt.NumParams)
	case StateHandshake1:
		tmpl += fmt.Sprintf("{schema:%q}", fsm.schema)
	}
	if len(msg) > 0 {
		tmpl += ": " + msg[0]
	}
	fsm.log.Sugar().Debugf(tmpl, StateName(from), StateName(to))
}

func (fsm *MySQLFSM) assertDir(exp reassembly.TCPFlowDirection) bool {
	return fsm.start < len(fsm.packets) && fsm.packets[fsm.start].Dir == exp
}

func (fsm *MySQLFSM) assertDataByte(offset int, exp byte) bool {
	data := fsm.data.Bytes()
	if len(data) <= offset {
		return false
	}
	return data[offset] == exp
}

func (fsm *MySQLFSM) assertDataChunk(offset int, exp []byte) bool {
	data := fsm.data.Bytes()
	if len(data) < offset+len(exp) {
		return false
	}
	return bytes.Equal(data[offset:offset+len(exp)], exp)
}

func (fsm *MySQLFSM) isClientCommand(cmd byte) bool {
	if !fsm.assertDir(reassembly.TCPDirClientToServer) {
		return false
	}
	return fsm.assertDataByte(0, cmd)
}

func (fsm *MySQLFSM) isHandshakeRequest() bool {
	if !fsm.assertDir(reassembly.TCPDirServerToClient) {
		return false
	}
	data := fsm.data.Bytes()
	if len(data) < 6 {
		return false
	}
	return data[0] == handshakeV9 || data[0] == handshakeV10
}

func (fsm *MySQLFSM) handleInitPacket() {
	if !fsm.load(0) {
		fsm.set(StateUnknown, "init: cannot load packet")
		return
	}
	if fsm.isClientCommand(comQuery) {
		fsm.handleComQueryNoLoad()
	} else if fsm.isClientCommand(comStmtExecute) {
		fsm.handleComStmtExecuteNoLoad()
	} else if fsm.isClientCommand(comStmtPrepare) {
		fsm.handleComStmtPrepareRequestNoLoad()
	} else if fsm.isClientCommand(comStmtClose) {
		fsm.handleComStmtCloseNoLoad()
	} else if fsm.isClientCommand(comQuit) {
		fsm.set(StateComQuit)
	} else if fsm.isHandshakeRequest() {
		fsm.set(StateHandshake0)
	} else {
		if fsm.assertDir(reassembly.TCPDirClientToServer) && fsm.data.Len() > 0 {
			fsm.set(StateUnknown, fmt.Sprintf("init: skip client command(0x%02x)", fsm.data.Bytes()[0]))
		} else {
			fsm.set(StateUnknown, "init: unsupported packet")
		}
	}
}

func (fsm *MySQLFSM) handleComQueryNoLoad() {
	fsm.query = string(fsm.data.Bytes()[1:])
	fsm.set(StateComQuery)
}

func (fsm *MySQLFSM) handleComStmtExecuteNoLoad() {
	var (
		ok     bool
		id     uint32
		stmt   Stmt
		params []interface{}
	)
	data := fsm.data.Bytes()[1:]
	if id, data, ok = readUint32(data); !ok {
		fsm.set(StateUnknown, "stmt execute: cannot read stmt id")
		return
	}
	if stmt, ok = fsm.stmts[id]; !ok {
		fsm.set(StateUnknown, "stmt execute: unknown stmt id")
		return
	}
	if _, data, ok = readBytesN(data, 5); !ok {
		fsm.set(StateUnknown, "stmt execute: cannot read flag and iteration-count")
		return
	}
	if stmt.NumParams > 0 {
		var (
			nullBitmaps []byte
			paramTypes  []byte
			paramValues []byte
			err         error
		)
		if nullBitmaps, data, ok = readBytesN(data, (stmt.NumParams+7)>>3); !ok {
			fsm.set(StateUnknown, "stmt execute: cannot read null-bitmap")
			return
		}
		if len(data) < 1+2*stmt.NumParams {
			fsm.set(StateUnknown, "stmt execute: cannot read params")
			return
		}
		if data[0] == 1 {
			paramTypes = data[1 : 1+(stmt.NumParams<<1)]
			paramValues = data[1+(stmt.NumParams<<1):]
			stmt.types = make([]byte, len(paramTypes))
			copy(stmt.types, paramTypes)
			fsm.stmts[id] = stmt
		} else {
			if stmt.types == nil {
				fsm.set(StateUnknown, "stmt execute: param types is missing")
				return
			}
			paramTypes = stmt.types
			paramValues = data[1:]
		}
		params, err = parseExecParams(stmt, nullBitmaps, paramTypes, paramValues)
		if err != nil {
			fsm.set(StateUnknown, "stmt execute: "+err.Error())
			return
		}
	}
	fsm.stmt = stmt
	fsm.params = params
	fsm.set(StateComStmtExecute)
}

func (fsm *MySQLFSM) handleComStmtCloseNoLoad() {
	stmtID, _, ok := readUint32(fsm.data.Bytes()[1:])
	if !ok {
		fsm.set(StateUnknown, "stmt close: cannot read stmt id")
		return
	}
	fsm.stmt = fsm.stmts[stmtID]
	delete(fsm.stmts, stmtID)
	fsm.set(StateComStmtClose)
}

func (fsm *MySQLFSM) handleComStmtPrepareRequestNoLoad() {
	fsm.stmt = Stmt{Query: string(fsm.data.Bytes()[1:])}
	fsm.set(StateComStmtPrepare0)
}

func (fsm *MySQLFSM) handleComStmtPrepareResponse() {
	if !fsm.load(1) {
		fsm.set(StateUnknown, "stmt prepare: cannot load packet")
		return
	}
	if !fsm.assertDir(reassembly.TCPDirServerToClient) {
		fsm.set(StateUnknown, "stmt prepare: unexpected packet direction")
		return
	}
	if !fsm.assertDataByte(0, 0) {
		fsm.set(StateUnknown, "stmt prepare: not ok")
		return
	}
	var (
		stmtID    uint32
		numParams uint16
		ok        bool
	)
	data := fsm.data.Bytes()[1:]
	if stmtID, data, ok = readUint32(data); !ok {
		fsm.set(StateUnknown, "stmt prepare: cannot read stmt id")
		return
	}
	if _, data, ok = readUint16(data); !ok {
		fsm.set(StateUnknown, "stmt prepare: cannot read number of columns")
		return
	}
	if numParams, data, ok = readUint16(data); !ok {
		fsm.set(StateUnknown, "stmt prepare: cannot read number of params")
		return
	}
	fsm.stmt.ID = stmtID
	fsm.stmt.NumParams = int(numParams)
	fsm.stmts[stmtID] = fsm.stmt
	fsm.set(StateComStmtPrepare1)
}

func (fsm *MySQLFSM) handleHandshakeResponse() {
	if !fsm.load(1) {
		fsm.set(StateUnknown, "handshake: cannot load packet")
		return
	}
	if !fsm.assertDir(reassembly.TCPDirClientToServer) {
		fsm.set(StateUnknown, "handshake: unexpected packet direction")
		return
	}
	var (
		flags clientFlag
		bs    []byte
		ok    bool
	)
	data := fsm.data.Bytes()
	if bs, data, ok = readBytesN(data, 2); !ok {
		fsm.set(StateUnknown, "handshake: cannot read capability flags")
		return
	}
	flags |= clientFlag(bs[0])
	flags |= clientFlag(bs[1]) << 8
	if flags&clientProtocol41 > 0 {
		if bs, data, ok = readBytesN(data, 2); !ok {
			fsm.set(StateUnknown, "handshake: cannot read extended capability flags")
			return
		}
		flags |= clientFlag(bs[0]) << 16
		flags |= clientFlag(bs[1]) << 24
		if _, data, ok = readBytesN(data, 28); !ok {
			fsm.set(StateUnknown, "handshake: cannot read max-packet size, character set and reserved")
			return
		}
		if _, data, ok = readBytesNUL(data); !ok {
			fsm.set(StateUnknown, "handshake: cannot read username")
			return
		}
		if flags&clientPluginAuthLenEncClientData > 0 {
			var n uint64
			if n, data, ok = readLenEncUint(data); !ok {
				fsm.set(StateUnknown, "handshake: cannot read length of auth-response")
				return
			}
			if _, data, ok = readBytesN(data, int(n)); !ok {
				fsm.set(StateUnknown, "handshake: cannot read auth-response")
				return
			}
		} else if flags&clientSecureConn > 0 {
			var n []byte
			if n, data, ok = readBytesN(data, 1); !ok {
				fsm.set(StateUnknown, "handshake: cannot read length of auth-response")
				return
			}
			if _, data, ok = readBytesN(data, int(n[0])); !ok {
				fsm.set(StateUnknown, "handshake: cannot read auth-response")
				return
			}
		} else {
			if _, data, ok = readBytesNUL(data); !ok {
				fsm.set(StateUnknown, "handshake: cannot read auth-response")
				return
			}
		}
		if flags&clientConnectWithDB > 0 {
			var db []byte
			if db, data, ok = readBytesNUL(data); !ok {
				fsm.set(StateUnknown, "handshake: cannot read database")
				return
			}
			fsm.schema = string(db)
		}
	} else {
		if _, data, ok = readBytesN(data, 3); !ok {
			fsm.set(StateUnknown, "handshake: cannot read max-packet size")
			return
		}
		if _, data, ok = readBytesNUL(data); !ok {
			fsm.set(StateUnknown, "handshake: cannot read username")
			return
		}
		if flags&clientConnectWithDB > 0 {
			var db []byte
			if _, data, ok = readBytesNUL(data); !ok {
				fsm.set(StateUnknown, "handshake: cannot read auth-response")
				return
			}
			if db, data, ok = readBytesNUL(data); !ok {
				fsm.set(StateUnknown, "handshake: cannot read database")
				return
			}
			fsm.schema = string(db)
		}
	}
	fsm.set(StateHandshake1)
}

func parseExecParams(stmt Stmt, nullBitmap []byte, paramTypes []byte, paramValues []byte) (params []interface{}, err error) {
	defer func() {
		if x := recover(); x != nil {
			params = nil
			err = errors.New("malformed packet")
		}
	}()
	pos := 0
	params = make([]interface{}, stmt.NumParams)
	for i := 0; i < stmt.NumParams; i++ {
		if nullBitmap[i>>3]&(1<<(uint(i)%8)) > 0 {
			params[i] = nil
			continue
		}
		if (i<<1)+1 >= len(paramTypes) {
			return nil, errors.New("malformed types")
		}
		tp := fieldType(paramTypes[i<<1])
		unsigned := (paramTypes[(i<<1)+1] & 0x80) > 0
		switch tp {
		case fieldTypeNULL:
			params[i] = nil
		case fieldTypeTiny:
			if len(paramValues) < pos+1 {
				return nil, errors.New("malformed values")
			}
			if unsigned {
				params[i] = uint64(paramValues[pos])
			} else {
				params[i] = int64(int8(paramValues[pos]))
			}
			pos += 1
		case fieldTypeShort, fieldTypeYear:
			if len(paramValues) < pos+2 {
				return nil, errors.New("malformed values")
			}
			val := binary.LittleEndian.Uint16(paramValues[pos : pos+2])
			if unsigned {
				params[i] = uint64(val)
			} else {
				params[i] = int64(int16(val))
			}
			pos += 2
		case fieldTypeInt24, fieldTypeLong:
			if len(paramValues) < pos+4 {
				return nil, errors.New("malformed values")
			}
			val := binary.LittleEndian.Uint32(paramValues[pos : pos+4])
			if unsigned {
				params[i] = uint64(val)
			} else {
				params[i] = int64(int32(val))
			}
			pos += 4
		case fieldTypeLongLong:
			if len(paramValues) < pos+8 {
				return nil, errors.New("malformed values")
			}
			val := binary.LittleEndian.Uint64(paramValues[pos : pos+8])
			if unsigned {
				params[i] = val
			} else {
				params[i] = int64(val)
			}
			pos += 8
		case fieldTypeFloat:
			if len(paramValues) < pos+4 {
				return nil, errors.New("malformed values")
			}
			params[i] = math.Float32frombits(binary.LittleEndian.Uint32(paramValues[pos : pos+4]))
			pos += 4
		case fieldTypeDouble:
			if len(paramValues) < pos+8 {
				return nil, errors.New("malformed values")
			}
			params[i] = math.Float64frombits(binary.LittleEndian.Uint64(paramValues[pos : pos+8]))
			pos += 8
		case fieldTypeDate, fieldTypeTimestamp, fieldTypeDateTime:
			if len(paramValues) < pos+1 {
				return nil, errors.New("malformed values")
			}
			length := paramValues[pos]
			pos += 1
			switch length {
			case 0:
				params[i] = "0000-00-00 00:00:00"
			case 4:
				pos, params[i] = parseBinaryDate(pos, paramValues)
			case 7:
				pos, params[i] = parseBinaryDateTime(pos, paramValues)
			case 11:
				pos, params[i] = parseBinaryTimestamp(pos, paramValues)
			default:
				return nil, errors.New("malformed values")
			}
		case fieldTypeTime:
			if len(paramValues) < pos+1 {
				return nil, errors.New("malformed values")
			}
			length := paramValues[pos]
			pos += 1
			switch length {
			case 0:
			case 8:
				if paramValues[pos] > 1 {
					return nil, errors.New("malformed values")
				}
				pos += 1
				pos, params[i] = parseBinaryTime(pos, paramValues, paramValues[pos-1])
			case 12:
				if paramValues[pos] > 1 {
					return nil, errors.New("malformed values")
				}
				pos += 1
				pos, params[i] = parseBinaryTimeWithMS(pos, paramValues, paramValues[pos-1])
			default:
				return nil, errors.New("malformed values")
			}
		case fieldTypeNewDecimal, fieldTypeDecimal, fieldTypeVarChar, fieldTypeVarString, fieldTypeString, fieldTypeEnum, fieldTypeSet, fieldTypeGeometry, fieldTypeBit:
			if len(paramValues) < pos+1 {
				return nil, errors.New("malformed values")
			}
			v, isNull, n, err := parseLengthEncodedBytes(paramValues[pos:])
			if err != nil {
				return nil, err
			}
			pos += n
			if isNull {
				params[i] = nil
			} else {
				params[i] = string(v)
			}
		case fieldTypeBLOB, fieldTypeTinyBLOB, fieldTypeMediumBLOB, fieldTypeLongBLOB:
			if len(paramValues) < pos+1 {
				return nil, errors.New("malformed values")
			}
			v, isNull, n, err := parseLengthEncodedBytes(paramValues[pos:])
			if err != nil {
				return nil, err
			}
			pos += n
			if isNull {
				params[i] = nil
			} else {
				params[i] = v
			}
		default:
			return nil, errors.New("unknown field type")
		}
	}

	return params, nil
}

func parseBinaryDate(pos int, paramValues []byte) (int, string) {
	year := binary.LittleEndian.Uint16(paramValues[pos : pos+2])
	pos += 2
	month := paramValues[pos]
	pos++
	day := paramValues[pos]
	pos++
	return pos, fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

func parseBinaryDateTime(pos int, paramValues []byte) (int, string) {
	pos, date := parseBinaryDate(pos, paramValues)
	hour := paramValues[pos]
	pos++
	minute := paramValues[pos]
	pos++
	second := paramValues[pos]
	pos++
	return pos, fmt.Sprintf("%s %02d:%02d:%02d", date, hour, minute, second)
}

func parseBinaryTimestamp(pos int, paramValues []byte) (int, string) {
	pos, dateTime := parseBinaryDateTime(pos, paramValues)
	microSecond := binary.LittleEndian.Uint32(paramValues[pos : pos+4])
	pos += 4
	return pos, fmt.Sprintf("%s.%06d", dateTime, microSecond)
}

func parseBinaryTime(pos int, paramValues []byte, isNegative uint8) (int, string) {
	sign := ""
	if isNegative == 1 {
		sign = "-"
	}
	days := binary.LittleEndian.Uint32(paramValues[pos : pos+4])
	pos += 4
	hours := paramValues[pos]
	pos++
	minutes := paramValues[pos]
	pos++
	seconds := paramValues[pos]
	pos++
	return pos, fmt.Sprintf("%s%d %02d:%02d:%02d", sign, days, hours, minutes, seconds)
}

func parseBinaryTimeWithMS(pos int, paramValues []byte, isNegative uint8) (int, string) {
	pos, dur := parseBinaryTime(pos, paramValues, isNegative)
	microSecond := binary.LittleEndian.Uint32(paramValues[pos : pos+4])
	pos += 4
	return pos, fmt.Sprintf("%s.%06d", dur, microSecond)
}

func parseLengthEncodedInt(b []byte) (num uint64, isNull bool, n int) {
	switch b[0] {
	// 251: NULL
	case 0xfb:
		n = 1
		isNull = true
		return

	// 252: value of following 2
	case 0xfc:
		num = uint64(b[1]) | uint64(b[2])<<8
		n = 3
		return

	// 253: value of following 3
	case 0xfd:
		num = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16
		n = 4
		return

	// 254: value of following 8
	case 0xfe:
		num = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16 |
			uint64(b[4])<<24 | uint64(b[5])<<32 | uint64(b[6])<<40 |
			uint64(b[7])<<48 | uint64(b[8])<<56
		n = 9
		return
	}

	// https://dev.mysql.com/doc/internals/en/integer.html#length-encoded-integer: If the first byte of a packet is a length-encoded integer and its byte value is 0xfe, you must check the length of the packet to verify that it has enough space for a 8-byte integer.
	// TODO: 0xff is undefined

	// 0-250: value of first byte
	num = uint64(b[0])
	n = 1
	return
}

func parseLengthEncodedBytes(b []byte) ([]byte, bool, int, error) {
	// Get length
	num, isNull, n := parseLengthEncodedInt(b)
	if num < 1 {
		return nil, isNull, n, nil
	}

	n += int(num)

	// Check data length
	if len(b) >= n {
		return b[n-int(num) : n], false, n, nil
	}

	return nil, false, n, io.EOF
}

func readUint16(data []byte) (uint16, []byte, bool) {
	if len(data) < 2 {
		return 0, data, false
	}
	return binary.LittleEndian.Uint16(data), data[2:], true
}

func readUint32(data []byte) (uint32, []byte, bool) {
	if len(data) < 4 {
		return 0, data, false
	}
	return binary.LittleEndian.Uint32(data), data[4:], true
}

func readBytesN(data []byte, n int) ([]byte, []byte, bool) {
	if len(data) < n {
		return nil, data, false
	}
	return data[:n], data[n:], true
}

func readBytesNUL(data []byte) ([]byte, []byte, bool) {
	for i, b := range data {
		if b == 0 {
			return data[:i], data[i+1:], true
		}
	}
	return nil, data, false
}

func readLenEncUint(data []byte) (uint64, []byte, bool) {
	if len(data) < 1 {
		return 0, data, false
	}
	if data[0] < 0xfb {
		return uint64(data[0]), data[1:], true
	} else if data[0] == 0xfc {
		if len(data) < 3 {
			return 0, data, false
		}
		return uint64(data[2]) | uint64(data[1])<<8, data[3:], true
	} else if data[0] == 0xfd {
		if len(data) < 4 {
			return 0, data, false
		}
		return uint64(data[3]) | uint64(data[2])<<8 | uint64(data[1])<<16, data[4:], true
	} else if data[0] == 0xfe {
		if len(data) < 9 {
			return 0, data, false
		}
		return binary.BigEndian.Uint64(data[1:]), data[9:], true
	} else {
		return 0, data, false
	}
}
