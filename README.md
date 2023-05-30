# perisco

eBPF based, L7 protocols monitoring solution in k8s.

Persico captures unencrypted L4 packets of host using eBPF. The packets are parsed into L7 protocol(HTTP, gRPC)'s header and then served in various path(file, elasticsearch, kafka etc.).

Perisco use [cilium/ebpf](https://github.com/cilium/ebpf) to load [eBPF](https://ebpf.io/) program.

## Requires

- Linux only 
- Linux kernel version near 5.15.0..?

## Why Perisco?

### There is already awesome project(cilium) as a network monitoring solution in k8s

`cilium-hubble` 모니터링 솔루션은 k8s cni로 cilium-cni를 사용하는 것을 전제로 합니다. Perisco 프로젝트는 특정한 cni에 종속되지 않는 독립적인 모니터링 솔루션을 제공하는 것을 목표로 합니다. 

### What is the difference from pixie?

같은 방식(eBPF 활용)으로 4계층 패킷을 읽어서 파싱하는 pixie 프로젝트가 이미 존재합니다. pixie는 암호화된 프로토콜인 http2, gRPC를 지원하기 위해 4계층이 아닌 7계층(uprobe)를 트레이싱하는 우회기법을 사용하고 있고, 헤더를 최대 30KiB 까지 읽는 단점들이 있습니다. Perisco 프로젝트는 암호화된 패킷은 깔끔하게 포기해서 구조를 간단하게 유지하면서 효율적인 처리를 할 수 있는 방향으로 진행했습니다.

Perisco는 ingress-controller에만 암호화를 사용하고 클러스터 내부 파드간 통신은 암호화를 사용하지 않는 사용 사례를 전제로 합니다. 암호화 계층이 내장되어있는 HTTP/2(+gRPC)의 경우, http2는 h2c(HTTP2 Cleartext), gRPC는 `insecure.NewCredentials()` 옵션을 사용하는 것을 전제로 합니다.

## Architecture

Perisco-agent는 DaemonSet을 통해 클러스터에 배포된 후, bpf 프로그램을 로드해서 특정 CIDR 범위의 네트워크 요청/응답을 추적합니다.

<img alt="k8s deployment" src="https://user-images.githubusercontent.com/44857109/194702483-1b6026b2-0591-41d8-a6f7-dca1ab140ce9.png">

응용 프로그램은 패킷의 데이터를 7계층 프로토콜로 파싱해서 네트워크 로그를 생성하는 작업을 수행합니다. 생성한 데이터는 저장을 위해 파일, 엘라스틱서치, 카프카(TODO) 등의 저장소로 전달합니다.

<img alt="persico internal" src="https://user-images.githubusercontent.com/44857109/236674811-4d86433d-adc6-409b-bee5-7f39e07d1dfe.png">

### eBPF

<img alt="bpf map" src="https://user-images.githubusercontent.com/44857109/236674728-37ffdf68-19b2-4d89-9710-8c3530bb3b77.png">

bpf 프로그램은 `inet_accept`, `sock_sendmsg`, `sock_recvmsg` Hook Points를 활용해서 파드간 송수신 이벤트를 추적하고 응용 프로그램쪽으로 전달하는 역할을 합니다. 이때 캡쳐하는 데이터의 크기는 최대 4KB이다. 다르게 말하면 프로토콜의 바디부분을 제외하고 헤더 부분의 크기가 4KB 이상이면 해당 요청/응답은 응용 프로그램쪽에서 파싱할 수 없습니다.

### Parser

<img alt="parser" src="https://user-images.githubusercontent.com/44857109/236674823-904ef2ce-0465-4afa-8441-30e7500758f5.png">

프로토콜 정보가 없는 데이터의 경우에 unknown parser를 통해 모든 프로토콜로 파싱을 시도하고

- 만약 성공한다면 이후에 수집된 데이터부터는 해당 프로토콜로 파싱
- 반대로 계속해서 파싱에 실패한다면 해당 서버의 송수신 이벤트는 차단

하는 구조입니다.

### Matcher

<img alt="matcher" src="https://user-images.githubusercontent.com/44857109/236674831-c0781442-09f2-4f46-9984-5e09d7b201a8.png">

각 소켓마다 매쳐 인스턴스를 생성해서 프로토콜의 헤더 구조에 따라 요청과 응답을 하나의 네트워크 로그로 합쳐주는 구조입니다.
HTTP 1.1의 파이프라인 같이 TCP 연결을 재사용하는 형태의 프로토콜을 고려해서 설계했습니다.

### Exporter

<img alt="exporter" src="https://github.com/KumKeeHyun/perisco/assets/44857109/c8c55bac-3abb-4759-bb90-f5dcf08b83ab">

프로세스 실행 시 전달받은 설정값에 따라서 인스턴스를 생성하고 
앞에서 생성된 메시지를 외부저장소에 저장하는 구조입니다.

## Example

Target to mornitoring msa  : [booksapp](https://github.com/BuoyantIO/booksapp)

<img alt="booksapp service map" src="https://github.com/BuoyantIO/booksapp/raw/main/images/topo.png">

```
perisco-agent -> elasticseasrch -> grafana
```

- sample network log

```
{"protoMessage":{"ts":"2023-04-11T03:43:29.619285359Z","pid":87111,"ip":{"client":"10.244.1.186","server":"10.244.1.42","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":38674,"serverPort":7002}},"l7":{"latencyNs":"8661819","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/books.json?order=lower%28title%29","headers":[{"key":"Keep-Alive","value":"30"},{"key":"Accept","value":"application/json"},{"key":"Accept-Encoding","value":"gzip;q=1.0,deflate;q=0.6,identity;q=0.3"},{"key":"User-Agent","value":"Ruby"},{"key":"Connection","value":"keep-alive"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"Connection","value":"Keep-Alive"},{"key":"Content-Type","value":"application/json"},{"key":"Content-Length","value":"2139"},{"key":"X-Content-Type-Options","value":"nosniff"}]}}}},"client":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"server":{"namespace":"default","labels":["app=books","pod-template-hash=675456b8d","project=booksapp"],"podName":"books-675456b8d-prpht"},"clientService":{"name":"webapp","namespace":"default"},"serverService":{"name":"books","namespace":"default"}}

{"protoMessage":{"ts":"2023-04-11T03:43:29.619285359Z","pid":87111,"ip":{"client":"10.244.1.186","server":"10.244.1.42","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":38674,"serverPort":7002}},"l7":{"latencyNs":"8661819","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/books.json?order=lower%28title%29","headers":[{"key":"Keep-Alive","value":"30"},{"key":"Accept","value":"application/json"},{"key":"Accept-Encoding","value":"gzip;q=1.0,deflate;q=0.6,identity;q=0.3"},{"key":"User-Agent","value":"Ruby"},{"key":"Connection","value":"keep-alive"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"Connection","value":"Keep-Alive"},{"key":"Content-Type","value":"application/json"},{"key":"Content-Length","value":"2139"},{"key":"X-Content-Type-Options","value":"nosniff"}]}}}},"client":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"server":{"namespace":"default","labels":["app=books","pod-template-hash=675456b8d","project=booksapp"],"podName":"books-675456b8d-prpht"},"clientService":{"name":"webapp","namespace":"default"},"serverService":{"name":"books","namespace":"default"}}

{"protoMessage":{"ts":"2023-04-11T03:43:29.631996674Z","pid":87071,"ip":{"client":"10.244.1.186","server":"10.244.1.34","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":34028,"serverPort":7001}},"l7":{"latencyNs":"4172939","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/authors.json?order=lower%28last_name%29","headers":[{"key":"Keep-Alive","value":"30"},{"key":"Accept","value":"application/json"},{"key":"Accept-Encoding","value":"gzip;q=1.0,deflate;q=0.6,identity;q=0.3"},{"key":"User-Agent","value":"Ruby"},{"key":"Connection","value":"keep-alive"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Content-Length","value":"1324"},{"key":"X-Content-Type-Options","value":"nosniff"},{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"Connection","value":"Keep-Alive"},{"key":"Content-Type","value":"application/json"}]}}}},"client":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"server":{"namespace":"default","labels":["project=booksapp","app=authors","app.kubernetes.io/part-of=booksapp","pod-template-hash=79887c5578"],"podName":"authors-79887c5578-f2q6j"},"clientService":{"name":"webapp","namespace":"default"},"serverService":{"name":"authors","namespace":"default"}}

{"protoMessage":{"ts":"2023-04-11T03:43:29.614625406Z","pid":87091,"ip":{"client":"10.244.2.24","server":"10.244.1.186","ipVersion":"IPv4"},"l4":{"TCP":{"clientPort":38398,"serverPort":7000}},"l7":{"latencyNs":"24627386","request":{"http":{"protocol":"HTTP/1.1","method":"GET","url":"/","headers":[{"key":"Accept","value":"*/*"},{"key":"User-Agent","value":"curl/7.38.0"}]}},"response":{"http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Connection","value":"Keep-Alive"},{"key":"Set-Cookie","value":"rack.session=BAh7CUkiD3Nlc3Npb25faWQGOgZFVG86HVJhY2s6OlNlc3Npb246OlNlc3Npb25JZAY6D0BwdWJsaWNfaWRJIkUyZDlmNTMzNjk2Yjk0NTgxZjQwYjZmZTY4ZGQxMjJjMWZiYzExYzEzNTQzZjJkODU4M2NiNWE4MDc1MjQ5YTllBjsARkkiCWNzcmYGOwBGSSIxY0pxTEh6czFaeVJVZ21aVGdncys5YlVIK01qS3VyMXk4ekY0aHF6ZkhRdz0GOwBGSSINdHJhY2tpbmcGOwBGewZJIhRIVFRQX1VTRVJfQUdFTlQGOwBUSSItOGI1NzhkOWRmYmY0NzUwY2RkZWY5MDcyNjZlNmY0NmNmYWNiNjI2YQY7AEZJIg5fX0ZMQVNIX18GOwBGewA%3D--b34e8f90a8eb064bbb09c72d37ac9a372a6bfde9; path=/; HttpOnly"},{"key":"Content-Length","value":"20993"},{"key":"Server","value":"WEBrick/1.6.0 (Ruby/2.7.1/2020-03-31)"},{"key":"Date","value":"Tue, 11 Apr 2023 03:43:30 GMT"},{"key":"X-Frame-Options","value":"SAMEORIGIN"},{"key":"Content-Type","value":"text/html;charset=utf-8"},{"key":"X-Xss-Protection","value":"1; mode=block"},{"key":"X-Content-Type-Options","value":"nosniff"}]}}}},"client":{"namespace":"default","labels":["pod-template-hash=5c66d66744","project=booksapp","app=traffic"],"podName":"traffic-5c66d66744-dxbcb"},"server":{"namespace":"default","labels":["app=webapp","app.kubernetes.io/part-of=booksapp","pod-template-hash=5f459f867b","project=booksapp"],"podName":"webapp-5f459f867b-2zbx8"},"serverService":{"name":"webapp","namespace":"default"}}
```

- Example Grafana Dashboard

![perisco-grafana-250x](https://github.com/KumKeeHyun/perisco/assets/44857109/5fb4c1c6-944b-4606-8cfe-b936eb858925)
