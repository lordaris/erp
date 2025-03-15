// Package transactiontype represents the transaction type in the system.
package transactiontype

import "fmt"

// The set of types that can be used.
const (
	Intake     = "INTAKE"     // Adding inventory through purchase or receipt
	Consume    = "CONSUME"    // Using up inventory
	Adjust     = "ADJUST"     // Manual adjustment (count, damage, etc.)
	Move       = "MOVE"       // Moving between locations
	Production = "PRODUCTION" // Used in manufacturing
	Return     = "RETURN"     // Return to inventory
)

// Set of known transaction types.
var transactionTypes = map[string]bool{
	Intake:     true,
	Consume:    true,
	Adjust:     true,
	Move:       true,
	Production: true,
	Return:     true,
}

// TransactionType represents a type of inventory transaction.
type TransactionType struct {
	value string
}

// String returns the string representation of the TransactionType.
func (t TransactionType) String() string {
	return t.value
}

// Equal provides support for the go-cmp package and testing.
func (t TransactionType) Equal(t2 TransactionType) bool {
	return t.value == t2.value
}

// MarshalText provides support for logging and any marshal needs.
func (t TransactionType) MarshalText() ([]byte, error) {
	return []byte(t.value), nil
}

// Parse parses the string value and returns a transaction type if one exists.
func Parse(value string) (TransactionType, error) {
	if !transactionTypes[value] {
		return TransactionType{}, fmt.Errorf("invalid transaction type %q", value)
	}

	return TransactionType{value}, nil
}

// MustParse parses the string value and returns a transaction type if one exists. If
// an error occurs the function panics.
func MustParse(value string) TransactionType {
	transactionType, err := Parse(value)
	if err != nil {
		panic(err)
	}

	return transactionType
}
