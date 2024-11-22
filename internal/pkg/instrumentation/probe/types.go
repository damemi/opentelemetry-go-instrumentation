// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package probe provides instrumentation probe types and definitions.
package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"go.opentelemetry.io/auto/internal/pkg/inject"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/bpffs"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe/sampling"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/utils"
	"go.opentelemetry.io/auto/internal/pkg/process"
	"go.opentelemetry.io/auto/internal/pkg/structfield"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

var ErrInvalidConfig = errors.New("invalid config type for Probe")

// TracingConfig provides base configuration options for trace-based TelemetryProbes.
type TracingConfig struct {
	SamplingConfig *sampling.Config
}

type TargetExecutableConfig struct {
	Executable    *link.Executable
	TargetDetails *process.TargetDetails
}

// BasicProbe is a provided implementation of BaseProbe. It is the base configuration
// and identification layer for any Probe.
type BasicProbe[C Config] struct {
	// ProbeID is a unique identifier for the Probe.
	ProbeID ID
	// ProbeConfig is the Config for this Probe.
	ProbeConfig C
	// Logger is used to log operations and errors.
	Logger *slog.Logger
}

// ID returns the ID for this Probe.
func (b *BasicProbe[C]) ID() ID {
	return b.ProbeID
}

// Config returns the Config for this Probe.
func (b *BasicProbe[C]) Config() Config {
	return b.ProbeConfig
}

// ApplyConfig attempts to apply the provided Config to this Probe.
func (b *BasicProbe[C]) ApplyConfig(newConfig Config) error {
	if config, ok := newConfig.(C); !ok {
		b.ProbeConfig = config
	} else {
		return ErrInvalidConfig
	}
	return nil
}

// GetLogger returns the Logger for this Probe.
func (b *BasicProbe[C]) GetLogger() *slog.Logger {
	return b.Logger
}

// TargetExecutableProbe is a provided implementation of ProcessProbe.
type TargetExecutableProbe[C Config, BPFObj any] struct {
	BasicProbe[C]
	*TargetExecutableConfig

	// Consts are the constants that need to be injected into the eBPF program
	// that is run by this Probe. Currently only used by TargetingProbes.
	Consts []Const

	// SpecFn is a creation function for an eBPF CollectionSpec related to the
	// probe.
	SpecFn func() (*ebpf.CollectionSpec, error)

	closers    []io.Closer
	collection *ebpf.Collection
	reader     *perf.Reader
	// Uprobes is a the collection of eBPF programs that need to be attached to
	// the target process.
	Uprobes []Uprobe
}

func (p *TargetExecutableProbe[C, BPFObj]) TargetConfig() *TargetExecutableConfig {
	return p.TargetExecutableConfig
}

// Load loads the eBPF programs for this Probe into memory.
func (p *TargetExecutableProbe[C, BPFObj]) Load() error {
	spec, err := p.SpecFn()
	if err != nil {
		return err
	}

	// Inject Consts into the Probe's collection spec.
	// TODO: Support Const injection for non-targeting probes.
	var opts []inject.Option
	for _, cnst := range p.Consts {
		o, e := cnst.InjectOption(p.TargetDetails)
		err = errors.Join(err, e)
		if e == nil && o != nil {
			opts = append(opts, o)
		}
	}
	if err != nil {
		return err
	}
	err = inject.Constants(spec, opts...)
	if err != nil {
		return err
	}

	// Set up closers for the Probe
	obj := new(BPFObj)
	if c, ok := ((interface{})(obj)).(io.Closer); ok {
		p.closers = append(p.closers, c)
	}

	// Initialize the eBPF collection for the Probe
	sOpts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpffs.PathForTargetApplication(p.TargetDetails),
		},
	}
	c, err := utils.InitializeEBPFCollection(spec, sOpts)
	if err != nil {
		return err
	}
	p.collection = c

	return nil
}

// Attach attaches loaded eBPF programs to trigger points and initializes the Probe.
func (p *TargetExecutableProbe[C, BPFObj]) Attach() error {
	// Attach Uprobes
	for _, up := range p.Uprobes {
		links, err := up.load(p.Executable, p.TargetDetails, p.collection)
		if err != nil {
			if up.Optional {
				p.Logger.Debug("failed to attach optional uprobe", "probe", p.ID, "symbol", up.Sym, "error", err)
				continue
			}
			return err
		}
		for _, l := range links {
			p.closers = append(p.closers, l)
		}
	}

	// Initialize reader for the Probe
	buf, ok := p.collection.Maps[DefaultBufferMapName]
	if !ok {
		return fmt.Errorf("%s map not found", DefaultBufferMapName)
	}
	var err error
	p.reader, err = perf.NewReader(buf, PerfBufferDefaultSizeInPages*os.Getpagesize())
	if err != nil {
		return err
	}
	p.closers = append(p.closers, p.reader)

	//TODO -- WIP -- ADD SAMPLING MANAGER CALLBACK
	return nil
}

// Manifest returns the Probe's instrumentation Manifest.
func (p *TargetExecutableProbe[C, BPFObj]) Manifest() Manifest {
	var structFieldIDs []structfield.ID
	for _, cnst := range p.Consts {
		if sfc, ok := cnst.(StructFieldConst); ok {
			structFieldIDs = append(structFieldIDs, sfc.Val)
		}
	}

	symbols := make([]FunctionSymbol, 0, len(p.Uprobes))
	for _, up := range p.Uprobes {
		symbols = append(symbols, FunctionSymbol{Symbol: up.Sym, DependsOn: up.DependsOn})
	}

	return NewManifest(p.ProbeID, structFieldIDs, symbols)
}

func (p *TargetExecutableProbe[C, BPFObj]) Close() error {
	if p.collection != nil {
		p.collection.Close()
	}
	var err error
	for _, c := range p.closers {
		err = errors.Join(err, c.Close())
	}
	if err == nil {
		p.Logger.Debug("Closed", "Probe", p.ID)
	}
	return err
}

// TargetEventProducingProbe is a Probe that reads eBPF events.
type TargetEventProducingProbe[C Config, BPFObj any, BPFEvent any] struct {
	TargetExecutableProbe[C, BPFObj]

	// ProcessRecord is an optional processing function for the probe. If nil,
	// all records will be read directly into a new BPFEvent using the
	// encoding/binary package.
	ProcessRecord func(perf.Record) (BPFEvent, error)
}

// read reads a new BPFEvent from the perf Reader.
func (e *TargetEventProducingProbe[C, BPFObj, BPFEvent]) read() (*BPFEvent, error) {
	record, err := e.reader.Read()
	if err != nil {
		if !errors.Is(err, perf.ErrClosed) {
			e.Logger.Error("error reading from perf reader", "error", err)
		}
		return nil, err
	}

	if record.LostSamples != 0 {
		e.Logger.Debug("perf event ring buffer full", "dropped", record.LostSamples)
		return nil, err
	}

	var event BPFEvent
	if e.ProcessRecord != nil {
		event, err = e.ProcessRecord(record)
	} else {
		buf := bytes.NewReader(record.RawSample)
		err = binary.Read(buf, binary.LittleEndian, &event)
	}

	if err != nil {
		return nil, err
	}
	return &event, nil
}

// TargetSpanProducingProbe is a provided implementation of TelemetryProbe that
// processes and handles ptrace.ScopeSpans.
type TargetSpanProducingProbe[C Config, BPFObj any, BPFEvent any] struct {
	TargetEventProducingProbe[C, BPFObj, BPFEvent]
	*TracingConfig

	Version   string
	SchemaURL string
	ProcessFn func(*BPFEvent) ptrace.SpanSlice

	Handler   func(ptrace.ScopeSpans)
}

func (s *TargetSpanProducingProbe[C, BPFObj, BPFEvent]) TraceConfig() *TracingConfig {
	return s.TracingConfig
}

func (s *TargetSpanProducingProbe[C, BPFObj, BPFEvent]) Run() {
	for {
		event, err := s.read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			continue
		}

		ss := ptrace.NewScopeSpans()

		ss.Scope().SetName("go.opentelemetry.io/auto/" + s.ProbeID.InstrumentedPkg)
		ss.Scope().SetVersion(s.Version)
		ss.SetSchemaUrl(s.SchemaURL)

		s.ProcessFn(event).CopyTo(ss.Spans())

		s.Handler(ss)
	}
}

type TargetTraceProducingProbe[C Config, BPFObj any, BPFEvent any] struct {
	TargetEventProducingProbe[C, BPFObj, BPFEvent]
	TracingConfig

	ProcessFn func(*BPFEvent) ptrace.ScopeSpans

	Handler   func(ptrace.ScopeSpans)
}

// Run runs the events processing loop.
func (i *TargetTraceProducingProbe[C, BPFObj, BPFEvent]) Run() {
	for {
		event, err := i.read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			continue
		}

		i.Handler(i.ProcessFn(event))
	}
}
