package protocols

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
)

type Http1RequestResult struct {
	Method string
	Path   string
	Header http.Header
}

func (r *Http1RequestResult) String() string {
	return fmt.Sprintf("[ method: %s, path: %s, header: %v ]", r.Method, r.Path, r.Header)
}

type Http1ResponseResult struct {
	Status     string
	StatusCode int
	Header     http.Header
}

func (r *Http1ResponseResult) String() string {
	return fmt.Sprintf("[ status: %s, statusCode: %d, header: %v ]", r.Status, r.StatusCode, r.Header)
}

func isValidMethod(method string) bool {
	switch method {
	case http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodHead,
		http.MethodOptions,
		http.MethodConnect,
		http.MethodTrace:
		return true
	default:
		return false
	}
}

type Http1Parser struct{}

var _ Parser = &Http1Parser{}

// ParseRequest implements protocols.Parser
func (*Http1Parser) ParseRequest(rawBytes []byte) (RequestResult, error) {
	b := bufio.NewReader(bytes.NewReader(rawBytes))

	req, err := http.ReadRequest(b)
	if err != nil {
		return nil, err
	}
	req.Body.Close()

	if !isValidMethod(req.Method) {
		return nil, fmt.Errorf("invalid method. got: %s", req.Method)
	}

	return &Http1RequestResult{
		Method: req.Method,
		Path:   req.URL.Path,
		Header: req.Header,
	}, nil
}

// ParseResponse implements protocols.Parser
func (*Http1Parser) ParseResponse(rawBytes []byte) (ResponseResult, error) {
	b := bufio.NewReader(bytes.NewReader(rawBytes))

	resp, err := http.ReadResponse(b, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return &Http1ResponseResult{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
	}, nil
}
