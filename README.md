# perisco

> still in development... I'm serving in ROK Air-Force soldier until `23.01.11. This project will proceed slowly.

eBPF based, L7 protocols monitoring solution in k8s.

Persico captures unencrypted L4 packets of host using eBPF. The packets are parsed into L7 protocol(HTTP, gRPC)'s header and then served in various path(file, elasticsearch, kafka etc.).

Perisco use [cilium/ebpf](#https://github.com/cilium/ebpf) to load [eBPF](#https://ebpf.io/) program.

## Requires

- Linux only 
- Linux kernel version near 5.15.0..?

## Why Perisco?

### There is already awesome project(cilium) as a network monitoring solution in k8s

`cilium-hubble` 솔루션은 k8s cni로 cilium-cni를 사용하는 것을 전제로 한다. 즉 cilium-cni에 종속적이다. perisco는 cni 독립적인 모니터링 솔루션을 제공하는 것을 목표로 한다. 

### What is the difference from pixie?

그럼 같은 방식으로 4계층 패킷을 읽어서 파싱하는 pixie와 다른점은 무엇인가? pixie는 암호화된 프로토콜인 http2, gRPC를 지원하기 위해 4계층이 아닌 7계층(uprobe)를 트레이싱하는 우회기법을 사용하고 있다. perisco는 암호화된 패킷은 깔끔하게 포기해서 구조를 최대한 단순하게 유지하려 한다. 

perisco는 ingress-controller에만 암호화를 사용하고 마이크로서비스간 통신은 암호화를 사용하지 않는 사용 사례를 전제로 한다. 즉, http2는 h2c(HTTP2 Cleartext), gRPC는 `insecure.NewCredentials()` 옵션을 사용하는 것을 전제로 한다.

## temp result

```
{"ts":{"seconds":1664880849,"nanos":189706873},"pid":3719,"ip":{"client":"127.0.0.1","server":"127.0.0.1","ipVersion":1},"l4":{"Protocol":{"TCP":{"client_port":47994,"server_port":8880}}},"l7":{"latency_ns":57508,"request":{"Record":{"Http":{"protocol":"HTTP/1.1","method":"GET","url":"/greet","headers":[{"key":"User-Agent","value":"Go-http-client/1.1"},{"key":"Accept-Encoding","value":"gzip"}]}}},"response":{"Record":{"Http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Date","value":"Tue, 04 Oct 2022 10:54:09 GMT"},{"key":"Content-Length","value":"20"},{"key":"Content-Type","value":"text/plain; charset=utf-8"}]}}}}}
{"ts":{"seconds":1664880858,"nanos":559773238},"pid":3719,"ip":{"client":"127.0.0.1","server":"127.0.0.1","ipVersion":1},"l4":{"Protocol":{"TCP":{"client_port":45152,"server_port":8880}}},"l7":{"latency_ns":205285,"request":{"Record":{"Http":{"protocol":"HTTP/1.1","method":"POST","url":"/push","headers":[{"key":"User-Agent","value":"Go-http-client/1.1"},{"key":"Content-Length","value":"20636"},{"key":"Content-Type","value":"application/json"},{"key":"Accept-Encoding","value":"gzip"}]}}},"response":{"Record":{"Http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Date","value":"Tue, 04 Oct 2022 10:54:18 GMT"},{"key":"Content-Length","value":"11"},{"key":"Content-Type","value":"text/plain; charset=utf-8"}]}}}}}
{"ts":{"seconds":1664880870,"nanos":58526313},"pid":3719,"ip":{"client":"127.0.0.1","server":"127.0.0.1","ipVersion":1},"l4":{"Protocol":{"TCP":{"client_port":51278,"server_port":8880}}},"l7":{"latency_ns":140746,"request":{"Record":{"Http":{"protocol":"HTTP/1.1","method":"GET","url":"/pull","headers":[{"key":"User-Agent","value":"Go-http-client/1.1"},{"key":"Accept-Encoding","value":"gzip"}]}}},"response":{"Record":{"Http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Date","value":"Tue, 04 Oct 2022 10:54:30 GMT"},{"key":"Content-Type","value":"application/octet-stream"}]}}}}}
{"ts":{"seconds":1664880871,"nanos":761256425},"pid":1292,"ip":{"client":"78.108.177.51","server":"127.0.0.1","ipVersion":1},"l4":{"Protocol":{"TCP":{"client_port":37974,"server_port":8080}}},"l7":{"latency_ns":4334145,"request":{"Record":{"Http":{"protocol":"HTTP/1.0","method":"GET","url":"/","headers":[{"key":"User-Agent","value":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0;  Trident/5.0)"},{"key":"Accept","value":"*/*"}]}}},"response":{"Record":{"Http":{"protocol":"HTTP/1.1","code":302,"headers":[{"key":"Location","value":"./login"},{"key":"Vary","value":"Accept, Accept-Encoding"},{"key":"Content-Type","value":"text/plain; charset=utf-8"},{"key":"Content-Length","value":"29"},{"key":"Date","value":"Tue, 04 Oct 2022 10:54:32 GMT"}]}}}}}
{"ts":{"seconds":1664880885,"nanos":415488689},"pid":3719,"ip":{"client":"127.0.0.1","server":"127.0.0.1","ipVersion":1},"l4":{"Protocol":{"TCP":{"client_port":33536,"server_port":8880}}},"l7":{"latency_ns":207638,"request":{"Record":{"Http":{"protocol":"HTTP/1.1","method":"GET","url":"/static/example.jpg","headers":[{"key":"User-Agent","value":"Go-http-client/1.1"},{"key":"Accept-Encoding","value":"gzip"}]}}},"response":{"Record":{"Http":{"protocol":"HTTP/1.1","code":200,"headers":[{"key":"Accept-Ranges","value":"bytes"},{"key":"Content-Length","value":"102117"},{"key":"Content-Type","value":"image/jpeg"},{"key":"Last-Modified","value":"Mon, 05 Sep 2022 09:37:53 GMT"},{"key":"Date","value":"Tue, 04 Oct 2022 10:54:45 GMT"}]}}}}}

```
