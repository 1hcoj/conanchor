package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/conanchor/conanchor-ebpf/internal/event"
)

type Printer struct {
	enc *json.Encoder
}

func NewPrinter(w io.Writer) *Printer {
	return &Printer{enc: json.NewEncoder(w)}
}

func (p *Printer) Print(evt event.Event) error {
	if err := p.enc.Encode(evt); err != nil {
		return fmt.Errorf("print jsonl event: %w", err)
	}
	return nil
}
