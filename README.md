# perisco
eBPF based, networks monitoring solution in k8s

## temp result

1. trace point : `sock_recvmsg`, `sock_sendmsg`
2. parse raw bytes to header -> http/1.1, http/2(grpc)
3. match request and response

- http/1.1

[testdata](./perisco/testing/http1.1)

```
2022/09/12 07:10:42 network filter: [0.0.0.0/0]
2022/09/12 07:11:06 detected HTTP/1.1 in endpoint(127.0.0.1:8880 pid:62565)
2022/09/12 07:11:06 new proto matcher of HTTP/1.1 for 127.0.0.1:8880 pid:62565
2022/09/12 07:11:10 127.0.0.1:8880  127.0.0.1:51224  IPv4/TCP  pid:62565 0 ms
HTTP/1.1 GET /greet 127.0.0.1:8880
map[Accept-Encoding:[gzip] User-Agent:[Go-http-client/1.1]]
HTTP/1.1 200 OK
map[Content-Length:[20] Content-Type:[text/plain; charset=utf-8] Date:[Mon, 12 Sep 2022 07:11:10 GMT]]

2022/09/12 07:11:15 127.0.0.1:8880  127.0.0.1:51240  IPv4/TCP  pid:62565 0 ms
HTTP/1.1 POST /push 127.0.0.1:8880
map[Accept-Encoding:[gzip] Content-Length:[20636] Content-Type:[application/json] User-Agent:[Go-http-client/1.1]]
HTTP/1.1 200 OK
map[Content-Length:[11] Content-Type:[text/plain; charset=utf-8] Date:[Mon, 12 Sep 2022 07:11:15 GMT]]

2022/09/12 07:11:29 127.0.0.1:8880  127.0.0.1:38266  IPv4/TCP  pid:62565 0 ms
HTTP/1.1 GET /static/example.jpg 127.0.0.1:8880
map[Accept-Encoding:[gzip] User-Agent:[Go-http-client/1.1]]
HTTP/1.1 200 OK
map[Accept-Ranges:[bytes] Content-Length:[102117] Content-Type:[image/jpeg] Date:[Mon, 12 Sep 2022 07:11:29 GMT] Last-Modified:[Mon, 05 Sep 2022 09:37:53 GMT]]
```

- http/2

[testdata](./perisco/testing/h2c)

```
2022/09/12 07:13:07 network filter: [0.0.0.0/0]
2022/09/12 07:13:10 detected HTTP/2 in endpoint(127.0.0.1:8881 pid:63362)
2022/09/12 07:13:10 new proto matcher of HTTP/2 for 127.0.0.1:8881 pid:63362
2022/09/12 07:13:20 127.0.0.1:8881  127.0.0.1:49160  IPv4/TCP  pid:63362 0 ms
[header field ":authority" = "127.0.0.1:8881" header field ":method" = "GET" header field ":path" = "/greet" header field ":scheme" = "http" header field "accept-encoding" = "gzip" header field "user-agent" = "Go-http-client/2.0"]
[header field ":status" = "200" header field "content-type" = "text/plain; charset=utf-8" header field "content-length" = "15" header field "date" = "Mon, 12 Sep 2022 07:13:20 GMT"]

2022/09/12 07:13:29 127.0.0.1:8881  127.0.0.1:41112  IPv4/TCP  pid:63362 0 ms
[header field ":authority" = "127.0.0.1:8881" header field ":method" = "POST" header field ":path" = "/push" header field ":scheme" = "http" header field "content-type" = "application/json" header field "content-length" = "20636" header field "accept-encoding" = "gzip" header field "user-agent" = "Go-http-client/2.0"]
[header field ":status" = "200" header field "content-type" = "text/plain; charset=utf-8" header field "content-length" = "11" header field "date" = "Mon, 12 Sep 2022 07:13:29 GMT"]

2022/09/12 07:13:34 127.0.0.1:8881  127.0.0.1:41114  IPv4/TCP  pid:63362 0 ms
[header field ":authority" = "127.0.0.1:8881" header field ":method" = "GET" header field ":path" = "/pull" header field ":scheme" = "http" header field "accept-encoding" = "gzip" header field "user-agent" = "Go-http-client/2.0"]
[header field ":status" = "200" header field "content-type" = "application/octet-stream" header field "date" = "Mon, 12 Sep 2022 07:13:34 GMT"]

2022/09/12 07:16:31 127.0.0.1:8881  127.0.0.1:47192  IPv4/TCP  pid:63362 0 ms
[header field ":authority" = "127.0.0.1:8881" header field ":method" = "GET" header field ":path" = "/redir" header field ":scheme" = "http" header field "accept-encoding" = "gzip" header field "user-agent" = "Go-http-client/2.0"]
[header field ":status" = "302" header field "content-type" = "text/html; charset=utf-8" header field "location" = "/greet" header field "content-length" = "29" header field "date" = "Mon, 12 Sep 2022 07:16:31 GMT"]

2022/09/12 07:16:31 127.0.0.1:8881  127.0.0.1:47192  IPv4/TCP  pid:63362 0 ms
[header field ":authority" = "127.0.0.1:8881" header field ":method" = "GET" header field ":path" = "/greet" header field ":scheme" = "http" header field "referer" = "http://127.0.0.1:8881/redir" header field "accept-encoding" = "gzip" header field "user-agent" = "Go-http-client/2.0"]
[header field ":status" = "200" header field "content-type" = "text/plain; charset=utf-8" header field "content-length" = "15" header field "date" = "Mon, 12 Sep 2022 07:16:31 GMT"]
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