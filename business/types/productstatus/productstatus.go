package productstatus

import (
	"fmt"
	"strings"
)

// All valid ProductStatus values.
const (
	Active       = "ACTIVE"
	Inactive     = "INACTIVE"
	Discontinued = "DISCONTINUED"
	ComingSoon   = "COMING_SOON"
)

// Set of valid statuses. Used for validating a status is known.
var statuses = map[string]bool{
	Active:       true,
	Inactive:     true,
	Discontinued: true,
	ComingSoon:   true,
}

// ProductStatus represents the status of a product.
type ProductStatus struct {
	value string
}

// New constructs a ProductStatus with the specified value.
func New(value string) (ProductStatus, error) {
	upValue := strings.ToUpper(strings.TrimSpace(value))

	if !statuses[upValue] {
		return ProductStatus{}, fmt.Errorf("invalid product status %q", value)
	}

	return ProductStatus{
		value: upValue,
	}, nil
}

// String returns the string representation of the ProductStatus.
func (p ProductStatus) String() string {
	return p.value
}

// Equals compares one ProductStatus with another for equality.
func (p ProductStatus) Equals(ps ProductStatus) bool {
	return p.value == ps.value
}

// Parse parses a string into a ProductStatus.
func Parse(value string) (ProductStatus, error) {
	return New(value)
}

// MustParse parses a string into a ProductStatus and panics if there's an error.
func MustParse(value string) ProductStatus {
	ps, err := Parse(value)
	if err != nil {
		panic(err)
	}
	return ps
}
