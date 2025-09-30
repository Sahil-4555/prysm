package query_test

import (
	"testing"

	"github.com/OffchainLabs/prysm/v6/encoding/ssz/query"
	"github.com/OffchainLabs/prysm/v6/testing/require"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []query.PathElement
		wantErr  bool
	}{
		{
			name: "simple nested path",
			path: "data.target.root",
			expected: []query.PathElement{
				{Name: "data"},
				{Name: "target"},
				{Name: "root"},
			},
			wantErr: false,
		},
		{
			name: "simple nested path with leading dot",
			path: ".data.target.root",
			expected: []query.PathElement{
				{Name: "data"},
				{Name: "target"},
				{Name: "root"},
			},
			wantErr: false,
		},
		{
			name: "path with array index",
			path: "validator[42].slashed",
			expected: []query.PathElement{
				{Name: "validator", Index: uint64Ptr(42)},
				{Name: "slashed"},
			},
			wantErr: false,
		},
		{
			name:     "empty path",
			path:     "",
			expected: nil,
			wantErr:  false,
		},
		{
			name: "single field",
			path: "root",
			expected: []query.PathElement{
				{Name: "root"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedPath, err := query.ParsePath(tt.path)

			if tt.wantErr {
				require.NotNil(t, err, "Expected error but got none")
				return
			}

			require.NoError(t, err)
			require.Equal(t, len(tt.expected), len(parsedPath), "Expected %d path elements, got %d", len(tt.expected), len(parsedPath))
			
			// Handle empty slice comparison
			if len(tt.expected) == 0 && len(parsedPath) == 0 {
				return
			}
			
			require.DeepEqual(t, tt.expected, parsedPath, "Parsed path does not match expected path")
		})
	}
}

// BenchmarkParsePath benchmarks the ParsePath function with various input patterns
func BenchmarkParsePath(b *testing.B) {
	benchmarks := []struct {
		name string
		path string
	}{
		// Simple paths
		{"simple_single_field", "root"},
		{"simple_two_fields", "data.root"},
		{"simple_three_fields", "data.target.root"},
		{"simple_four_fields", "state.data.target.root"},
		
		// Paths with array indices
		{"array_single_index", "validator[0]"},
		{"array_with_field", "validator[42].slashed"},
		{"array_with_nested", "validators[100].data.balance"},
		{"array_multiple", "state[5].validators[42].slashed"},
		
		// Paths with leading dot
		{"leading_dot_simple", ".data.root"},
		{"leading_dot_array", ".validator[42].slashed"},
		
		// Deep nested paths
		{"deep_nesting_5", "a.b.c.d.e"},
		{"deep_nesting_10", "a.b.c.d.e.f.g.h.i.j"},
		
		// Long field names
		{"long_field_name", "attestation_data.beacon_block_root"},
		{"long_nested_names", "attestation.data.source.epoch"},
		
		// Complex real-world examples
		{"complex_beacon_state", "validators[1000].effective_balance"},
		{"complex_attestation", "attestation.data.target.root"},
		{"complex_block", "body.attestations[5].data.slot"},
		
		// Edge cases
		{"empty_path", ""},
		{"only_dot", "."},
		{"multiple_dots", "..."},
		{"large_index", "validator[999999].slashed"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = query.ParsePath(bm.path)
			}
		})
	}
}

// BenchmarkParsePathParallel benchmarks ParsePath with parallel execution
func BenchmarkParsePathParallel(b *testing.B) {
	paths := []string{
		"validator[42].slashed",
		"data.target.root",
		"attestation.data.source.epoch",
		"validators[1000].effective_balance",
	}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			path := paths[i%len(paths)]
			_, _ = query.ParsePath(path)
			i++
		}
	})
}

// BenchmarkParsePathCached tests if caching would be beneficial
func BenchmarkParsePathRepeated(b *testing.B) {
	// Simulate real-world scenario where same paths are parsed repeatedly
	commonPaths := []string{
		"validator[42].slashed",
		"data.target.root",
		"state.slot",
	}

	b.Run("repeated_paths", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			path := commonPaths[i%len(commonPaths)]
			_, _ = query.ParsePath(path)
		}
	})
}

// BenchmarkParsePathByComplexity groups benchmarks by path complexity
func BenchmarkParsePathByComplexity(b *testing.B) {
	tests := []struct {
		complexity string
		paths      []string
	}{
		{
			complexity: "simple",
			paths: []string{
				"root",
				"slot",
				"epoch",
			},
		},
		{
			complexity: "medium",
			paths: []string{
				"data.root",
				"target.epoch",
				"source.root",
			},
		},
		{
			complexity: "complex",
			paths: []string{
				"attestation.data.target.root",
				"validators[100].effective_balance",
				"body.attestations[5].data.slot",
			},
		},
		{
			complexity: "very_complex",
			paths: []string{
				"state.validators[1000].data.balance.effective",
				"block.body.attestations[42].data.source.epoch",
				"beacon.state.data[5].validators[100].slashed",
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.complexity, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				path := tt.paths[i%len(tt.paths)]
				_, _ = query.ParsePath(path)
			}
		})
	}
}

// BenchmarkParsePathMemory focuses on memory allocations
func BenchmarkParsePathMemory(b *testing.B) {
	paths := []string{
		"validator[42].slashed",
		"data.target.root",
		"attestation.data.source.epoch.root.hash",
	}

	for _, path := range paths {
		b.Run(path, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, _ := query.ParsePath(path)
				_ = result
			}
		})
	}
}

// Helper function for tests
func uint64Ptr(i uint64) *uint64 {
	return &i
}