// Package location represents a location in the system.
package location

import (
	"fmt"
	"regexp"
)

// Location represents a location in the system.
type Location struct {
	value string
}

// String returns the value of the location.
func (l Location) String() string {
	return l.value
}

// Equal provides support for the go-cmp package and testing.
func (l Location) Equal(l2 Location) bool {
	return l.value == l2.value
}

// MarshalText provides support for logging and any marshal needs.
func (l Location) MarshalText() ([]byte, error) {
	return []byte(l.value), nil
}

// =============================================================================

var locationRegEx = regexp.MustCompile("^[A-Z]-[0-9]{1,3}-[0-9]{1,3}$")

// Parse parses the string value and returns a location if the value complies
// with the rules for a location.
func Parse(value string) (Location, error) {
	if !locationRegEx.MatchString(value) {
		return Location{}, fmt.Errorf("invalid location %q, must match format: A-123-123", value)
	}

	return Location{value}, nil
}

// MustParse parses the string value and returns a location if the value
// complies with the rules for a location. If an error occurs the function panics.
func MustParse(value string) Location {
	location, err := Parse(value)
	if err != nil {
		panic(err)
	}

	return location
}
