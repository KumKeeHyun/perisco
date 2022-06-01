# perisco
eBPF based, networks monitoring solution in k8s

## temp result

1. trace point : `sock_recvmsg`, `sock_sendmsg`
2. parse raw bytes -> http/1.1, http/2(grpc)

- http/1.1

[testdata](./perisco/testing/http1.1)

```
2022/06/01 04:16:01 127.0.0.1       8880     127.0.0.1       51242   CONN      
2022/06/01 04:16:01 127.0.0.1       8880     127.0.0.1       51242   REQUEST   
ret: 100   [HTTP/1.1   127.0.0.1:8880  GET        /redir header: map[Accept-Encoding:[gzip] User-Agent:[Go-http-client/1.1]]]
2022/06/01 04:16:01 127.0.0.1       8880     127.0.0.1       51242   RESPONSE  
ret: 0     [HTTP/1.1   302 Found       header: map[Content-Length:[29] Content-Type:[text/html; charset=utf-8] Date:[Wed, 01 Jun 2022 04:16:01 GMT] Location:[/greet]]]
2022/06/01 04:16:01 127.0.0.1       8880     127.0.0.1       51242   REQUEST   
ret: 138   [HTTP/1.1   127.0.0.1:8880  GET        /greet header: map[Accept-Encoding:[gzip] Referer:[http://127.0.0.1:8880/redir] User-Agent:[Go-http-client/1.1]]]
2022/06/01 04:16:01 127.0.0.1       8880     127.0.0.1       51242   RESPONSE  
ret: 0     [HTTP/1.1   200 OK          header: map[Content-Length:[20] Content-Type:[text/plain; charset=utf-8] Date:[Wed, 01 Jun 2022 04:16:01 GMT]]]

2022/06/01 04:16:09 127.0.0.1       8880     127.0.0.1       51244   CONN      
2022/06/01 04:16:09 127.0.0.1       8880     127.0.0.1       51244   REQUEST   
ret: 4096  [HTTP/1.1   127.0.0.1:8880  POST       /push header: map[Accept-Encoding:[gzip] Content-Length:[20636] Content-Type:[application/json] User-Agent:[Go-http-client/1.1]]]
2022/06/01 04:16:09 127.0.0.1       8880     127.0.0.1       51244   RESPONSE  
ret: 0     [HTTP/1.1   200 OK          header: map[Content-Length:[11] Content-Type:[text/plain; charset=utf-8] Date:[Wed, 01 Jun 2022 04:16:09 GMT]]]

2022/06/01 04:19:24 127.0.0.1       8880     127.0.0.1       51246   CONN      
2022/06/01 04:19:24 127.0.0.1       8880     127.0.0.1       51246   REQUEST   
ret: 113   [HTTP/1.1   127.0.0.1:8880  GET        /static/example.jpg header: map[Accept-Encoding:[gzip] User-Agent:[Go-http-client/1.1]]]
2022/06/01 04:19:24 127.0.0.1       8880     127.0.0.1       51246   RESPONSE  
ret: 0     [HTTP/1.1   200 OK          header: map[Accept-Ranges:[bytes] Content-Length:[102117] Content-Type:[image/jpeg] Date:[Wed, 01 Jun 2022 04:19:24 GMT] Last-Modified:[Wed, 01 Jun 2022 03:38:46 GMT]]]
```

- http/2

[testdata](./perisco/testing/h2c)

```
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   CONN      
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   REQUEST   
ret: 64    [FrameHeader SETTINGS len=18]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   REQUEST   
ret: 64    [FrameHeader WINDOW_UPDATE len=4]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   RESPONSE  
ret: 0     [FrameHeader SETTINGS len=24]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   RESPONSE  
ret: 0     [FrameHeader SETTINGS flags=ACK len=0]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   RESPONSE  
ret: 0     [FrameHeader WINDOW_UPDATE len=4]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   REQUEST   
ret: 9     [FrameHeader SETTINGS flags=ACK len=0]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   REQUEST   
ret: 49    [header field ":authority" = "127.0.0.1:8881" header field ":method" = "GET" header field ":path" = "/test" header field ":scheme" = "http" header field "accept-encoding" = "gzip" header field "user-agent" = "Go-http-client/2.0"]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   RESPONSE  
ret: 0     [header field ":status" = "200" header field "content-type" = "text/plain; charset=utf-8" header field "content-length" = "15" header field "date" = "Wed, 01 Jun 2022 04:21:47 GMT"]
2022/06/01 04:21:47 127.0.0.1       8881     127.0.0.1       46220   RESPONSE  
ret: 0     [DataFrame hello! from h2c]
```

- grpc

[testdata](./perisco/testing/grpc)

```
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   RESPONSE  
ret: 0     [FrameHeader SETTINGS len=6]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   REQUEST   
ret: 9     [FrameHeader SETTINGS len=0]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   RESPONSE  
ret: 0     [FrameHeader SETTINGS flags=ACK len=0]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   CONN      
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   REQUEST   
ret: 112   [FrameHeader SETTINGS flags=ACK len=0]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   REQUEST   
ret: 112   [header field ":method" = "POST" header field ":scheme" = "http" header field ":path" = "/hello.HelloService/SayHello" header field ":authority" = "127.0.0.1:8882" header field "content-type" = "application/grpc" header field "user-agent" = "grpc-go/1.46.0" header field "te" = "trailers"]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   REQUEST   
ret: 112   [DataFrame 
hello]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   RESPONSE  
ret: 0     [FrameHeader WINDOW_UPDATE len=4]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   RESPONSE  
ret: 0     [FrameHeader PING len=8]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   RESPONSE  
ret: 0     [header field ":status" = "200" header field "content-type" = "application/grpc"]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   RESPONSE  
ret: 0     [DataFrame 
hello! from grpc]
2022/06/01 04:23:13 127.0.0.1       8882     127.0.0.1       58298   RESPONSE  
ret: 0     [header field "grpc-status" = "0" header field "grpc-message" = ""]
```