package segment

// SegmentJSON defines a KCP Segment that can be serialized to JSON
type SegmentJSON struct {
	Conv     uint32 `json:"conv"`     // conversation ID
	Cmd      uint8  `json:"cmd"`      // command: PUSH, ACK, WASK, WINS
	Frg      uint8  `json:"frg"`      // fragment index
	Wnd      uint16 `json:"wnd"`      // window size
	Ts       uint32 `json:"ts"`       // timestamp
	Sn       uint32 `json:"sn"`       // sequence number
	Una      uint32 `json:"una"`      // unacknowledged sequence number
	Rto      uint32 `json:"rto"`      // retransmission timeout
	Xmit     uint32 `json:"xmit"`     // transmit count
	Resendts uint32 `json:"resendts"` // resend timestamp
	Fastack  uint32 `json:"fastack"`  // fast ack count
	Acked    uint32 `json:"acked"`    // acked flag
	Data     string `json:"data"`     // payload data
}
