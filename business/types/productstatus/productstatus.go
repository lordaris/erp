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

// Equal provides support for the go-cmp package and testing.
func (p ProductStatus) Equal(ps ProductStatus) bool {
	return p.value == ps.value
}

// Equals is an alias for Equal for backwards compatibility.
func (p ProductStatus) Equals(ps ProductStatus) bool {
	return p.Equal(ps)
}

// MarshalText provides support for logging and any marshal needs.
func (p ProductStatus) MarshalText() ([]byte, error) {
	return []byte(p.value), nil
}

// IsActive returns true if the product status is Active.
func (p ProductStatus) IsActive() bool {
	return p.value == Active
}

// IsDiscontinued returns true if the product status is Discontinued.
func (p ProductStatus) IsDiscontinued() bool {
	return p.value == Discontinued
}

// IsComingSoon returns true if the product status is ComingSoon.
func (p ProductStatus) IsComingSoon() bool {
	return p.value == ComingSoon
}

// IsInactive returns true if the product status is Inactive.
func (p ProductStatus) IsInactive() bool {
	return p.value == Inactive
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

// Values returns a slice of all valid product status values.
func Values() []string {
	values := make([]string, 0, len(statuses))
	for status := range statuses {
		values = append(values, status)
	}
	return values
}

// Validate checks if a given string is a valid product status.
func Validate(value string) bool {
	upValue := strings.ToUpper(strings.TrimSpace(value))
	_, exists := statuses[upValue]
	return exists
}
