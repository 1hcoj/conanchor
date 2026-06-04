package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/conanchor/conanchor-ebpf/internal/container"
	"github.com/conanchor/conanchor-ebpf/internal/event"
	"github.com/conanchor/conanchor-ebpf/internal/output"
)

func main() {
	log.SetFlags(0)

	if err := run(); err != nil {
		log.Fatalf("collector: %v", err)
	}
}

func run() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs conanchorObjects
	if err := loadConanchorObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	links, err := attachLSMPrograms(&objs)
	if err != nil {
		return err
	}
	for _, l := range links {
		defer l.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()

	ctxResolver := container.NewResolver()
	printer := output.NewPrinter(os.Stdout)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		evt, err := event.Decode(record.RawSample)
		if err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		containerCtx := ctxResolver.Resolve(evt.PID, evt.CgroupID)
		evt.ContainerID = containerCtx.ContainerID
		evt.ContainerInstanceID = containerCtx.ContainerInstanceID

		if !event.ShouldEmit(evt) {
			continue
		}
		if err := printer.Print(evt); err != nil {
			return err
		}
	}
}

func attachLSMPrograms(objs *conanchorObjects) ([]link.Link, error) {
	programs := []struct {
		name string
		prog *ebpf.Program
	}{
		{name: "bprm_check_security", prog: objs.HandleBprmCheckSecurity},
		{name: "file_open", prog: objs.HandleFileOpen},
		{name: "sb_mount", prog: objs.HandleSbMount},
	}

	links := make([]link.Link, 0, len(programs))
	for _, p := range programs {
		l, err := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if err != nil {
			for _, opened := range links {
				_ = opened.Close()
			}
			return nil, fmt.Errorf("attach LSM %s: %w", p.name, err)
		}
		links = append(links, l)
	}
	return links, nil
}
