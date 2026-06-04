package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	targetCgroupIDs := flag.String("target-cgroup-id", os.Getenv("CONANCHOR_TARGET_CGROUP_ID"), "comma-separated cgroup IDs to monitor in kernel space; empty monitors all cgroups")
	flag.Parse()

	if err := run(*targetCgroupIDs); err != nil {
		log.Fatalf("collector: %v", err)
	}
}

func run(targetCgroupIDs string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs conanchorObjects
	if err := loadConanchorObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	if err := configureTargetCgroups(&objs, targetCgroupIDs); err != nil {
		return err
	}

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

func configureTargetCgroups(objs *conanchorObjects, csv string) error {
	ids, err := parseCgroupIDs(csv)
	if err != nil {
		return err
	}

	var zero uint32
	enabled := uint32(0)
	if len(ids) > 0 {
		enabled = 1
	}
	if err := objs.FilterEnabled.Update(zero, enabled, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("configure cgroup filter state: %w", err)
	}

	for _, id := range ids {
		allowed := uint8(1)
		if err := objs.TargetCgroups.Update(id, allowed, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure target cgroup %d: %w", id, err)
		}
	}
	return nil
}

func parseCgroupIDs(csv string) ([]uint64, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}

	parts := strings.Split(csv, ",")
	ids := make([]uint64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseUint(part, 10, 64)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("invalid cgroup id %q", part)
		}
		ids = append(ids, id)
	}
	return ids, nil
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
