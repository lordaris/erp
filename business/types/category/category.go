package category

import (
	"fmt"
	"strings"
)

// Category represents a product category.
type Category struct {
	value string
}

// New constructs a Category with the specified value.
func New(value string) (Category, error) {
	if len(strings.TrimSpace(value)) < 2 {
		return Category{}, fmt.Errorf("invalid category %q", value)
	}

	return Category{
		value: strings.TrimSpace(value),
	}, nil
}

// String returns the string representation of the Category.
func (c Category) String() string {
	return c.value
}

// Equals compares one Category with another for equality.
func (c Category) Equals(cat Category) bool {
	return c.value == cat.value
}

// Parse parses a string into a Category.
func Parse(value string) (Category, error) {
	return New(value)
}

// MustParse parses a string into a Category and panics if there's an error.
func MustParse(value string) Category {
	cat, err := Parse(value)
	if err != nil {
		panic(err)
	}
	return cat
}
