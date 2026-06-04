package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
)

type rawEvent struct {
	TimestampNS uint64
	EventType   uint32
	PID         uint32
	TGID        uint32
	UID         uint32
	GID         uint32
	_           uint32
	CgroupID    uint64
	Comm        [16]byte
	Path        [256]byte
	Extra       [256]byte
	Flags       uint64
	Retval      int32
}

func Decode(raw []byte) (Event, error) {
	var re rawEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return Event{}, fmt.Errorf("decode raw event: %w", err)
	}

	evt := Event{
		TimestampNS: re.TimestampNS,
		EventType:   decodeType(re.EventType),
		PID:         re.PID,
		TGID:        re.TGID,
		UID:         re.UID,
		GID:         re.GID,
		Comm:        cString(re.Comm[:]),
		Path:        cString(re.Path[:]),
		Extra:       cString(re.Extra[:]),
		Flags:       re.Flags,
		Retval:      re.Retval,
		CgroupID:    strconv.FormatUint(re.CgroupID, 10),
	}
	Classify(&evt)
	return evt, nil
}

func decodeType(t uint32) EventType {
	switch t {
	case rawEventExec:
		return EventExec
	case rawEventFileOpen:
		return EventFileOpen
	case rawEventMount:
		return EventMount
	default:
		return EventType("unknown")
	}
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
