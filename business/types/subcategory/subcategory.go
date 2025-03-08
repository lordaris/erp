package subcategory

import (
	"fmt"
	"strings"
)

// Subcategory represents a product subcategory.
type Subcategory struct {
	value string
}

// New constructs a Subcategory with the specified value.
func New(value string) (Subcategory, error) {
	if len(strings.TrimSpace(value)) < 2 {
		return Subcategory{}, fmt.Errorf("invalid subcategory %q", value)
	}

	return Subcategory{
		value: strings.TrimSpace(value),
	}, nil
}

// String returns the string representation of the Subcategory.
func (s Subcategory) String() string {
	return s.value
}

// Equals compares one Subcategory with another for equality.
func (s Subcategory) Equals(sub Subcategory) bool {
	return s.value == sub.value
}

// Parse parses a string into a Subcategory.
func Parse(value string) (Subcategory, error) {
	return New(value)
}

// MustParse parses a string into a Subcategory and panics if there's an error.
func MustParse(value string) Subcategory {
	sub, err := Parse(value)
	if err != nil {
		panic(err)
	}
	return sub
}
