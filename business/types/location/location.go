package location

import "fmt"

// The set of types that can be used.
const (
	Receiving  = "RECEIVING"  // Where goods are received
	Storage    = "STORAGE"    // Main storage area
	Shipping   = "SHIPPING"   // Staging area for outgoing shipments
	Production = "PRODUCTION" // Where manufacturing takes place
	Returns    = "RETURNS"    // Area for processing returns
)

// Set of known location types.
var locationTypes = map[string]bool{
	Receiving:  true,
	Storage:    true,
	Shipping:   true,
	Production: true,
	Returns:    true,
}

// LocationType represents a type of storage location.
type LocationType struct {
	value string
}

// String returns the string representation of the LocationType.
func (l LocationType) String() string {
	return l.value
}

// Equal provides support for the go-cmp package and testing.
func (l LocationType) Equal(l2 LocationType) bool {
	return l.value == l2.value
}

// MarshalText provides support for logging and any marshal needs.
func (l LocationType) MarshalText() ([]byte, error) {
	return []byte(l.value), nil
}

// Parse parses the string value and returns a location type if one exists.
func Parse(value string) (LocationType, error) {
	if !locationTypes[value] {
		return LocationType{}, fmt.Errorf("invalid location type %q", value)
	}

	return LocationType{value}, nil
}

// MustParse parses the string value and returns a location type if one exists. If
// an error occurs the function panics.
func MustParse(value string) LocationType {
	locationType, err := Parse(value)
	if err != nil {
		panic(err)
	}

	return locationType
}
