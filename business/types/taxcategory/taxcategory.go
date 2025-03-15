package taxcategory

import (
	"fmt"
	"strings"
)

// All valid TaxCategory values.
const (
	Standard = "STANDARD"
	Reduced  = "REDUCED"
	Zero     = "ZERO"
	Exempt   = "EXEMPT"
)

// Set of valid tax categories. Used for validating a category is known.
var categories = map[string]bool{
	Standard: true,
	Reduced:  true,
	Zero:     true,
	Exempt:   true,
}

// TaxCategory represents a tax category for products.
type TaxCategory struct {
	value string
}

// New constructs a TaxCategory with the specified value.
func New(value string) (TaxCategory, error) {
	upValue := strings.ToUpper(strings.TrimSpace(value))

	if !categories[upValue] {
		return TaxCategory{}, fmt.Errorf("invalid tax category %q", value)
	}

	return TaxCategory{
		value: upValue,
	}, nil
}

// String returns the string representation of the TaxCategory.
func (t TaxCategory) String() string {
	return t.value
}

// Equals compares one TaxCategory with another for equality.
func (t TaxCategory) Equals(tc TaxCategory) bool {
	return t.value == tc.value
}

// Parse parses a string into a TaxCategory.
func Parse(value string) (TaxCategory, error) {
	return New(value)
}

// MustParse parses a string into a TaxCategory and panics if there's an error.
func MustParse(value string) TaxCategory {
	tc, err := Parse(value)
	if err != nil {
		panic(err)
	}
	return tc
}
