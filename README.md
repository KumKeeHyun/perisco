# perisco
eBPF based, networks monitoring solution in k8s

## 임시 결과

INET4 TCP 연결을 추적하여 다음 항목 데이터를 생성함.

```
2022/05/18 10:56:42 127.0.0.1       34040    127.0.0.1       8880    CLIENT     CONN    

2022/05/18 10:56:42 127.0.0.1       8880     127.0.0.1       34040   SERVER     CONN    

2022/05/18 10:56:42 127.0.0.1       34040    127.0.0.1       8880    CLIENT     REQUEST   
2022/05/18 10:56:42 nrSegs: 1, count: 99, offset: 0, size: 99, msg: GET /test HTTP/1.1
Host: 127.0.0.1:8880
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip


2022/05/18 10:56:42 127.0.0.1       8880     127.0.0.1       34040   SERVER     REQUEST   
2022/05/18 10:56:42 nrSegs: 1, count: 4096, offset: 0, size: 4096, msg: GET /test HTTP/1.1
Host: 127.0.0.1:8880
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip


2022/05/18 10:56:42 127.0.0.1       8880     127.0.0.1       34040   SERVER     RESPONSE  
2022/05/18 10:56:42 nrSegs: 1, count: 137, offset: 0, size: 137, msg: HTTP/1.1 200 OK
Date: Wed, 18 May 2022 10:56:42 GMT
Content-Length: 20
Content-Type: text/plain; charset=utf-8

hello! from http/1.1
2022/05/18 10:56:42 127.0.0.1       34040    127.0.0.1       8880    CLIENT     CLOSE       99         12288   

2022/05/18 10:56:42 127.0.0.1       34040    127.0.0.1       8880    CLIENT     RESPONSE  
2022/05/18 10:56:42 nrSegs: 1, count: 4096, offset: 0, size: 4096, msg: HTTP/1.1 200 OK
Date: Wed, 18 May 2022 10:56:42 GMT
Content-Length: 20
Content-Type: text/plain; charset=utf-8

hello! from http/1.1
```