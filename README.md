# perisco

eBPF based, L7 protocols monitoring solution in k8s.

Persico captures unencrypted L4 packets of host using eBPF. The packets are parsed into L7 protocol(HTTP, gRPC)'s header and then served in various path(file, elasticsearch, kafka etc.).

Perisco use [cilium/ebpf](https://github.com/cilium/ebpf) to load [eBPF](https://ebpf.io/) program.

## Requires

- Linux only 
- Linux kernel version near 5.15.0..?

## Why Perisco?

### There is already awesome project(cilium) as a network monitoring solution in k8s

`cilium-hubble` 솔루션은 k8s cni로 cilium-cni를 사용하는 것을 전제로 한다. 즉 cilium-cni에 종속적이다. perisco는 cni 독립적인 모니터링 솔루션을 제공하는 것을 목표로 한다. 

### What is the difference from pixie?

그럼 같은 방식으로 4계층 패킷을 읽어서 파싱하는 pixie와 다른점은 무엇인가? pixie는 암호화된 프로토콜인 http2, gRPC를 지원하기 위해 4계층이 아닌 7계층(uprobe)를 트레이싱하는 우회기법을 사용하고 있다. perisco는 암호화된 패킷은 깔끔하게 포기해서 구조를 최대한 단순하게 유지하려 한다. 

perisco는 ingress-controller에만 암호화를 사용하고 마이크로서비스간 통신은 암호화를 사용하지 않는 사용 사례를 전제로 한다. 즉, http2는 h2c(HTTP2 Cleartext), gRPC는 `insecure.NewCredentials()` 옵션을 사용하는 것을 전제로 한다.

## Architecture

perisco는 DaemonSet을 통해 클러스터에 배포된 후, bpf 프로그램을 로드해서 특정 CIDR 범위의 네트워크 요청/응답을 추적한다.

<img alt="k8s deployment" src="https://user-images.githubusercontent.com/44857109/194702483-1b6026b2-0591-41d8-a6f7-dca1ab140ce9.png">

bpf 프로그램은 `sock_sendmsg`, `sock_recvmsg` 함수에 Hook을 걸어 패킷의 데이터부분을 응용 프로그램쪽으로 전달하는 역할을 한다. 이때 캡쳐하는 데이터의 크기는 최대 4KB이다. 다르게 말하면 프로토콜의 바디부분을 제외하고 헤더 부분의 크기가 4KB 이상이면 해당 요청/응답은 응용 프로그램쪽에서 파싱할 수 없다.

`inet_accept`에 Hook을 걸어서 CIDR 기반으로 추적할 소켓의 범위를 제한한다.

<img alt="bpf map" src="https://user-images.githubusercontent.com/44857109/236674728-37ffdf68-19b2-4d89-9710-8c3530bb3b77.png">

응용 프로그램은 패킷의 데이터를 특정 프로토콜로 파싱한 뒤, 별개의 요청과 응답 부분을 매칭해서 하나의 데이터로 묶는 작업을 한다. 생성한 데이터는 영구 저장을 위해 파일, 카프카(TODO), 엘라스틱서치(TODO) 등의 저장소로 전달한다. 추가적으로 Hubble-UI를 사용할 수 있도록 Hubble Flow API를 구현할 예정이다.

<img alt="persico internal" src="https://user-images.githubusercontent.com/44857109/236674811-4d86433d-adc6-409b-bee5-7f39e07d1dfe.png">

### Parser

<img alt="parser" src="https://user-images.githubusercontent.com/44857109/236674823-904ef2ce-0465-4afa-8441-30e7500758f5.png">

### Matcher

<img alt="matcher" src="https://user-images.githubusercontent.com/44857109/236674831-c0781442-09f2-4f46-9984-5e09d7b201a8.png">

## temp result

test microservice : [booksapp](https://github.com/BuoyantIO/booksapp)

<img alt="booksapp service map" src="https://github.com/BuoyantIO/booksapp/raw/main/images/topo.png">

- file(stdout) output 

```
{"protoMessage":{"ts":"2023-04-11T03:43:29.619285359Z","pid":87111,"ip":{"client":"10.244.1.186","server":"10.244.1.42","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":38674,"serverPort":7002}},"l7":{"latencyNs":"8661819","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/books.json?order=lower%28title%29","headers":[{"key":"Keep-Alive","value":"30"},{"key":"Accept","value":"application/json"},{"key":"Accept-Encoding","value":"gzip;q=1.0,deflate;q=0.6,identity;q=0.3"},{"key":"User-Agent","value":"Ruby"},{"key":"Connection","value":"keep-alive"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"Connection","value":"Keep-Alive"},{"key":"Content-Type","value":"application/json"},{"key":"Content-Length","value":"2139"},{"key":"X-Content-Type-Options","value":"nosniff"}]}}}},"client":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"server":{"namespace":"default","labels":["app=books","pod-template-hash=675456b8d","project=booksapp"],"podName":"books-675456b8d-prpht"},"clientService":{"name":"webapp","namespace":"default"},"serverService":{"name":"books","namespace":"default"}}

{"protoMessage":{"ts":"2023-04-11T03:43:29.619285359Z","pid":87111,"ip":{"client":"10.244.1.186","server":"10.244.1.42","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":38674,"serverPort":7002}},"l7":{"latencyNs":"8661819","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/books.json?order=lower%28title%29","headers":[{"key":"Keep-Alive","value":"30"},{"key":"Accept","value":"application/json"},{"key":"Accept-Encoding","value":"gzip;q=1.0,deflate;q=0.6,identity;q=0.3"},{"key":"User-Agent","value":"Ruby"},{"key":"Connection","value":"keep-alive"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"Connection","value":"Keep-Alive"},{"key":"Content-Type","value":"application/json"},{"key":"Content-Length","value":"2139"},{"key":"X-Content-Type-Options","value":"nosniff"}]}}}},"client":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"server":{"namespace":"default","labels":["app=books","pod-template-hash=675456b8d","project=booksapp"],"podName":"books-675456b8d-prpht"},"clientService":{"name":"webapp","namespace":"default"},"serverService":{"name":"books","namespace":"default"}}

{"protoMessage":{"ts":"2023-04-11T03:43:29.631996674Z","pid":87071,"ip":{"client":"10.244.1.186","server":"10.244.1.34","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":34028,"serverPort":7001}},"l7":{"latencyNs":"4172939","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/authors.json?order=lower%28last_name%29","headers":[{"key":"Keep-Alive","value":"30"},{"key":"Accept","value":"application/json"},{"key":"Accept-Encoding","value":"gzip;q=1.0,deflate;q=0.6,identity;q=0.3"},{"key":"User-Agent","value":"Ruby"},{"key":"Connection","value":"keep-alive"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Content-Length","value":"1324"},{"key":"X-Content-Type-Options","value":"nosniff"},{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"Connection","value":"Keep-Alive"},{"key":"Content-Type","value":"application/json"}]}}}},"client":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"server":{"namespace":"default","labels":["project=booksapp","app=authors","app.kubernetes.io/part-of=booksapp","pod-template-hash=79887c5578"],"podName":"authors-79887c5578-f2q6j"},"clientService":{"name":"webapp","namespace":"default"},"serverService":{"name":"authors","namespace":"default"}}

{"protoMessage":{"ts":"2023-04-11T03:43:29.614625406Z","pid":87091,"ip":{"client":"10.244.2.24","server":"10.244.1.186","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":38398,"serverPort":7000}},"l7":{"latencyNs":"24627386","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/","headers":[{"key":"Accept","value":"*/*"},{"key":"User-Agent","value":"curl/7.38.0"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Connection","value":"Keep-Alive"},{"key":"Set-Cookie","value":"rack.session=BAh7CUkiD3Nlc3Npb25faWQGOgZFVG86HVJhY2s6OlNlc3Npb246OlNlc3Npb25JZAY6D0BwdWJsaWNfaWRJIkUyZDlmNTMzNjk2Yjk0NTgxZjQwYjZmZTY4ZGQxMjJjMWZiYzExYzEzNTQzZjJkODU4M2NiNWE4MDc1MjQ5YTllBjsARkkiCWNzcmYGOwBGSSIxY0pxTEh6czFaeVJVZ21aVGdncys5YlVIK01qS3VyMXk4ekY0aHF6ZkhRdz0GOwBGSSINdHJhY2tpbmcGOwBGewZJIhRIVFRQX1VTRVJfQUdFTlQGOwBUSSItOGI1NzhkOWRmYmY0NzUwY2RkZWY5MDcyNjZlNmY0NmNmYWNiNjI2YQY7AEZJIg5fX0ZMQVNIX18GOwBGewA%3D--b34e8f90a8eb064bbb09c72d37ac9a372a6bfde9; path=/; HttpOnly"},{"key":"Content-Length","value":"20993"},{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"X-Frame-Options","value":"SAMEORIGIN"},{"key":"Content-Type","value":"text/html;charset=utf-8"},{"key":"X-Xss-Protection","value":"1; mode=block"},{"key":"X-Content-Type-Options","value":"nosniff"}]}}}},"client":{"namespace":"default","labels":["pod-template-hash=5c66d66744","project=booksapp","app=traffic"],"podName":"traffic-5c66d66744-dxbcb"},"server":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"serverService":{"name":"webapp","namespace":"default"}}
```

- grafana test dashboard

<img alt="grafana test dashboard" src="https://user-images.githubusercontent.com/44857109/236675097-a50b52aa-daf4-48f7-9090-879415dd5d7d.png">