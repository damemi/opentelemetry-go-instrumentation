// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package opentelemetry

import (
	"context"
	"runtime"
	"time"

	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/auto"
	"go.opentelemetry.io/auto/pkg/instrumentors/events"
	"go.opentelemetry.io/auto/pkg/log"
)

// Controller handles OpenTelemetry telemetry generation for events.
type Controller struct {
	tracerProvider trace.TracerProvider
	tracersMap     map[string]trace.Tracer
	bootTime       int64
}

// ControllerSetting is a wrapper for params required to initialize Controller.
type ControllerSetting struct {
	ServiceName string
	Exporter    sdktrace.SpanExporter
}

func (c *Controller) getTracer(libName string) trace.Tracer {
	t, exists := c.tracersMap[libName]
	if exists {
		return t
	}

	newTracer := c.tracerProvider.Tracer(libName)
	c.tracersMap[libName] = newTracer
	return newTracer
}

// Trace creates a trace span for event.
func (c *Controller) Trace(event *events.Event) {
	log.Logger.V(0).Info("got event", "attrs", event.Attributes)
	ctx := context.Background()

	if event.SpanContext == nil {
		log.Logger.V(0).Info("got event without context - dropping")
	}

	// TODO: handle remote parent
	if event.ParentSpanContext != nil {
		ctx = trace.ContextWithSpanContext(ctx, *event.ParentSpanContext)
	}

	ctx = ContextWithEBPFEvent(ctx, *event)
	_, span := c.getTracer(event.Library).
		Start(ctx, event.Name,
			trace.WithAttributes(event.Attributes...),
			trace.WithSpanKind(event.Kind),
			trace.WithTimestamp(c.convertTime(event.StartTime)))
	span.End(trace.WithTimestamp(c.convertTime(event.EndTime)))
}

func (c *Controller) convertTime(t int64) time.Time {
	return time.Unix(0, c.bootTime+t)
}

// NewController returns a new initialized [Controller].
func NewController(
	ctx context.Context,
	settings ControllerSetting,
) (*Controller, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(settings.ServiceName),
			semconv.TelemetrySDKLanguageGo,
			semconv.TelemetryAutoVersionKey.String(auto.Version()),
		),
	)
	if err != nil {
		return nil, err
	}

	bsp := sdktrace.NewBatchSpanProcessor(settings.Exporter)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithIDGenerator(newEBPFSourceIDGenerator()),
	)

	bt, err := estimateBootTimeOffset()
	if err != nil {
		return nil, err
	}

	return &Controller{
		tracerProvider: tracerProvider,
		tracersMap:     make(map[string]trace.Tracer),
		bootTime:       bt,
	}, nil
}

func estimateBootTimeOffset() (bootTimeOffset int64, err error) {
	// The datapath is currently using ktime_get_boot_ns for the pcap timestamp,
	// which corresponds to CLOCK_BOOTTIME. To be able to convert the the
	// CLOCK_BOOTTIME to CLOCK_REALTIME (i.e. a unix timestamp).

	// There can be an arbitrary amount of time between the execution of
	// time.Now() and unix.ClockGettime() below, especially under scheduler
	// pressure during program startup. To reduce the error introduced by these
	// delays, we pin the current Go routine to its OS thread and measure the
	// clocks multiple times, taking only the smallest observed difference
	// between the two values (which implies the smallest possible delay
	// between the two snapshots).
	var minDiff int64 = 1<<63 - 1
	estimationRounds := 25
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for round := 0; round < estimationRounds; round++ {
		var bootTimespec unix.Timespec

		// Ideally we would use __vdso_clock_gettime for both clocks here,
		// to have as little overhead as possible.
		// time.Now() will actually use VDSO on Go 1.9+, but calling
		// unix.ClockGettime to obtain CLOCK_BOOTTIME is a regular system call
		// for now.
		unixTime := time.Now()
		err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTimespec)
		if err != nil {
			return 0, err
		}

		offset := unixTime.UnixNano() - bootTimespec.Nano()
		diff := offset
		if diff < 0 {
			diff = -diff
		}

		if diff < minDiff {
			minDiff = diff
			bootTimeOffset = offset
		}
	}

	return bootTimeOffset, nil
}
