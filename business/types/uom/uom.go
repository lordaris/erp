package uom

import (
	"fmt"
	"strings"
)

// All valid UnitOfMeasure values.
const (
	Each       = "EACH"
	Pair       = "PAIR"
	Kilogram   = "KG"
	Gram       = "G"
	Liter      = "L"
	Milliliter = "ML"
	Meter      = "M"
	Centimeter = "CM"
	Box        = "BOX"
	Pack       = "PACK"
)

// Set of valid units of measure. Used for validating a UoM is known.
var units = map[string]bool{
	Each:       true,
	Pair:       true,
	Kilogram:   true,
	Gram:       true,
	Liter:      true,
	Milliliter: true,
	Meter:      true,
	Centimeter: true,
	Box:        true,
	Pack:       true,
}

// UnitOfMeasure represents a unit of measure for products.
type UnitOfMeasure struct {
	value string
}

// New constructs a UnitOfMeasure with the specified value.
func New(value string) (UnitOfMeasure, error) {
	upValue := strings.ToUpper(strings.TrimSpace(value))

	if !units[upValue] {
		return UnitOfMeasure{}, fmt.Errorf("invalid unit of measure %q", value)
	}

	return UnitOfMeasure{
		value: upValue,
	}, nil
}

// String returns the string representation of the UnitOfMeasure.
func (u UnitOfMeasure) String() string {
	return u.value
}

// Equals compares one UnitOfMeasure with another for equality.
func (u UnitOfMeasure) Equals(uom UnitOfMeasure) bool {
	return u.value == uom.value
}

// Parse parses a string into a UnitOfMeasure.
func Parse(value string) (UnitOfMeasure, error) {
	return New(value)
}

// MustParse parses a string into a UnitOfMeasure and panics if there's an error.
func MustParse(value string) UnitOfMeasure {
	uom, err := Parse(value)
	if err != nil {
		panic(err)
	}
	return uom
}
