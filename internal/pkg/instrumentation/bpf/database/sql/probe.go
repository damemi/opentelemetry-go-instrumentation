// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"vitess.io/vitess/go/vt/sqlparser"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf ./bpf/probe.bpf.c

const (
	// pkg is the package being instrumented.
	pkg = "database/sql"

	// IncludeDBStatementEnvVar is the environment variable to opt-in for sql query inclusion in the trace.
	IncludeDBStatementEnvVar = "OTEL_GO_AUTO_INCLUDE_DB_STATEMENT"

	// IncludeDBOperationEnvVar is the environment variable to opt-in for sql query operation in the trace.
	IncludeDBOperationEnvVar = "OTEL_GO_AUTO_PARSE_DB_STATEMENT"
)

// New returns a new [probe.Probe].
func New(logger *slog.Logger, version string) probe.Probe {
	id := probe.ID{
		SpanKind:        trace.SpanKindClient,
		InstrumentedPkg: pkg,
	}
	return &probe.SpanProducer[bpfObjects, event]{
		Base: probe.Base[bpfObjects, event]{
			ID:     id,
			Logger: logger,
			Consts: []probe.Const{
				probe.RegistersABIConst{},
				probe.AllocationConst{},
				probe.KeyValConst{
					Key: "should_include_db_statement",
					Val: shouldIncludeDBStatement(),
				},
			},
			Uprobes: []probe.Uprobe{
				{
					Sym:         "database/sql.(*DB).queryDC",
					EntryProbe:  "uprobe_queryDC",
					ReturnProbe: "uprobe_queryDC_Returns",
					Optional:    true,
				},
				{
					Sym:         "database/sql.(*DB).execDC",
					EntryProbe:  "uprobe_execDC",
					ReturnProbe: "uprobe_execDC_Returns",
					Optional:    true,
				},
			},

			SpecFn: loadBpf,
		},
		Version:   version,
		SchemaURL: semconv.SchemaURL,
		ProcessFn: processFn,
	}
}

// event represents an event in an SQL database
// request-response.
type event struct {
	context.BaseSpanProperties
	Query [256]byte
}

func processFn(e *event) ptrace.SpanSlice {
	spans := ptrace.NewSpanSlice()
	span := spans.AppendEmpty()
	span.SetName("DB")
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(utils.BootOffsetToTimestamp(e.StartTime))
	span.SetEndTimestamp(utils.BootOffsetToTimestamp(e.EndTime))
	span.SetTraceID(pcommon.TraceID(e.SpanContext.TraceID))
	span.SetSpanID(pcommon.SpanID(e.SpanContext.SpanID))
	span.SetFlags(uint32(trace.FlagsSampled))

	if e.ParentSpanContext.SpanID.IsValid() {
		span.SetParentSpanID(pcommon.SpanID(e.ParentSpanContext.SpanID))
	}

	query := unix.ByteSliceToString(e.Query[:])
	if query != "" {
		span.Attributes().PutStr(string(semconv.DBQueryTextKey), query)
	}

	includeOperationVal := os.Getenv(IncludeDBOperationEnvVar)
	if includeOperationVal != "" {
		include, err := strconv.ParseBool(includeOperationVal)
		if err == nil && include {
			operation, tables, err := parseQuery(query)
			if err == nil {
				summary := ""
				if len(operation) > 0 {
					span.Attributes().PutStr(string(semconv.DBOperationNameKey), operation)
					summary = operation
				}
				if len(tables) > 0 {
					// TODO: figure out a heuristic besides just using the first table in the list of sql nodes
					span.Attributes().PutStr(string(semconv.DBCollectionNameKey), tables[0])
					// if we have an operation and table, build {db.query.summary} with {db.operation.name} + {target}
					if summary != "" {
						summary = fmt.Sprintf("%s %s", summary, tables[0])
					}
				}
				if summary != "" {
					span.SetName(summary)
				}
			}
		}
	}

	return spans
}

// shouldIncludeDBStatement returns if the user has configured SQL queries to be included.
func shouldIncludeDBStatement() bool {
	val := os.Getenv(IncludeDBStatementEnvVar)
	if val != "" {
		boolVal, err := strconv.ParseBool(val)
		if err == nil {
			return boolVal
		}
	}

	return false
}

// Parse takes a SQL query string and returns the parsed query statement type
// and table name(s), or an error if parsing failed.
func parseQuery(query string) (string, []string, error) {
	p, err := sqlparser.New(sqlparser.Options{})
	if err != nil {
		return "", nil, fmt.Errorf("failed to create parser: %w", err)
	}

	stmt, err := p.Parse(query)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse query: %w", err)
	}

	var statementType string
	var tables []string

	switch stmt := stmt.(type) {
	case *sqlparser.Select:
		statementType = "SELECT"
		tables = extractTables(stmt.From)
	case *sqlparser.Update:
		statementType = "UPDATE"
		tables = extractTables(stmt.TableExprs)
	case *sqlparser.Insert:
		statementType = "INSERT"
		tables = []string{stmt.Table.TableNameString()}
	case *sqlparser.Delete:
		statementType = "DELETE"
		tables = extractTables(stmt.TableExprs)
	case *sqlparser.CreateTable:
		statementType = "CREATE TABLE"
		tables = []string{stmt.Table.Name.String()}
	case *sqlparser.AlterTable:
		statementType = "ALTER TABLE"
		tables = []string{stmt.Table.Name.String()}
	case *sqlparser.TruncateTable:
		statementType = "TRUNCATE TABLE"
		tables = []string{stmt.Table.Name.String()}
	case *sqlparser.DropTable:
		statementType = "DROP TABLE"
		for _, table := range stmt.FromTables {
			tables = append(tables, table.Name.String())
		}
	case *sqlparser.CreateDatabase:
		statementType = "CREATE DATABASE"
		tables = []string{stmt.DBName.String()}
	case *sqlparser.DropDatabase:
		statementType = "DROP DATABASE"
		tables = []string{stmt.DBName.String()}
	default:
		return "UNKNOWN", nil, fmt.Errorf("unsupported statement type")
	}

	return statementType, tables, nil
}

// extractTables extracts table names from a list of SQL nodes.
func extractTables(exprs sqlparser.TableExprs) []string {
	var tables []string
	for _, expr := range exprs {
		switch tableExpr := expr.(type) {
		case *sqlparser.AliasedTableExpr:
			if name, ok := tableExpr.Expr.(sqlparser.TableName); ok {
				tables = append(tables, name.Name.String())
			}
		}
	}
	return tables
}
