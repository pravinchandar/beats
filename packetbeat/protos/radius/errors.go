package radius

// All dns protocol errors are defined here.

type Error interface {
	error
	ResponseError() string
}

type RadiusError struct {
	Err string
}

func (e *RadiusError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Err
}

func (e *RadiusError) ResponseError() string {
	return "Response: " + e.Error()
}

// Messages
var (
	NonRadiusMsg        = &RadiusError{Err: "Message's data could not be decoded as Radius"}
	ZeroLengthMsg       = &RadiusError{Err: "Message's length was set to zero"}
	UnexpectedLengthMsg = &RadiusError{Err: "Unexpected message data length"}
	DuplicateQueryMsg   = &RadiusError{Err: "Another query with the same Radius ID from this client " +
		"was received so this query was closed without receiving a response"}
	IncompleteMsg = &RadiusError{Err: "Message's data is incomplete"}
	NoResponse    = &RadiusError{Err: "No response to this query was received"}
)

// TCP responses
var (
	OrphanedResponse = &RadiusError{Err: "Response: received without an associated Query"}
)
