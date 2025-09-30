package query

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PathElement represents a single element in a path.
type PathElement struct {
	Name string
	// [Optional] Index for List/Vector elements
	Index *uint64
}

func ParsePath(rawPath string) ([]PathElement, error) {
	if rawPath == "" {
		return []PathElement{},	 nil
	}

	// Trim leading dot if present
	if rawPath[0] == '.' {
		rawPath = rawPath[1:]
		if rawPath == "" {
			return nil, errors.New("empty path provided")
		}
	}

	var path []PathElement

	start := 0
	for i := 0; i < len(rawPath); i++ {
		if rawPath[i] == '.' {
			if i == start {
				return nil, errors.New("invalid path: consecutive dots or trailing dot")
			}
			elem, err := parsePathElement(rawPath[start:i])
			if err != nil {
				return nil, err
			}
			path = append(path, elem)
			start = i + 1
		}
	}

	// Handle last element
	if start >= len(rawPath) {
		return nil, errors.New("invalid path: consecutive dots or trailing dot")
	}
	elem, err := parsePathElement(rawPath[start:])
	if err != nil {
		return nil, err
	}
	path = append(path, elem)

	return path, nil
}

// parsePathElement parses a single path element with optional index notation.
func parsePathElement(elem string) (PathElement, error) {
	if elem == "" {
		return PathElement{}, errors.New("invalid path: empty element")
	}

	// Find index notation
	indexStart := strings.IndexByte(elem, '[')
	if indexStart == -1 {
		return PathElement{Name: elem}, nil
	}

	// Validate format
	if indexStart == 0 {
		return PathElement{}, errors.New("field name cannot be empty before index")
	}
	if elem[len(elem)-1] != ']' {
		return PathElement{}, fmt.Errorf("invalid index notation in path element %s", elem)
	}

	fieldName := elem[:indexStart]
	indexStr := elem[indexStart+1 : len(elem)-1]

	if indexStr == "" {
		return PathElement{}, errors.New("index cannot be empty")
	}

	indexValue, err := strconv.ParseUint(indexStr, 10, 64)
	if err != nil {
		return PathElement{}, fmt.Errorf("invalid index in path element %s: %w", elem, err)
	}

	return PathElement{Name: fieldName, Index: &indexValue}, nil
}
