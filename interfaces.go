package steranko

import (
	"net/http"
	"net/url"
)

// Context represents the minimum interface that a multipass HTTP handler can depend on.
// It is essentially a subset of the echo.Context interface, and adapters will be written
// in github.com/benpate/multipass to bridge this API over to other routers.
type Context interface {

	// Request returns the raw HTTP request object that we're responding to
	Request() *http.Request

	// Path returns the registered path for the handler.
	Path() string

	// Language returns the default language used by the browser.
	Language() string

	// RealIP returns the client's network address based on `X-Forwarded-For`
	// or `X-Real-IP` request header.
	RealIP() string

	// ParamNames returns a slice of route parameter names that are present in the request path
	ParamNames() []string

	// Param returns the value of an individual route parameter in the request path
	Param(name string) string

	// QueryParams returns the raw values of all query parameters passed in the request URI.
	QueryParams() url.Values

	// FormParams returns the raw values of all form parameters passed in the request body.
	FormParams() (url.Values, error)

	// Bind binds the request body into provided type `i`. The default binder
	// does it based on Content-Type header.
	Bind(interface{}) error

	// JSON sends a JSON response with status code.
	JSON(code int, value interface{}) error

	// Text sends a text response with a status code.
	Text(code int, text string) error

	// HTML sends an HTTP response with status code.
	HTML(code int, html string) error

	// NoContent sends a response with no body and a status code.
	NoContent(code int) error
}
