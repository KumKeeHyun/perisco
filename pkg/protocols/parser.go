package protocols

type RequestResult interface {
	String() string
}

type ResponseResult interface {
	String() string
}

type Parser interface {
	ParseRequest([]byte) (RequestResult, error)
	ParseResponse([]byte) (ResponseResult, error)
}