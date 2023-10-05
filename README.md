# perisco

eBPF based, L7 protocols monitoring solution in k8s.

Persico captures unencrypted L4 packets of host using eBPF. The packets are parsed into L7 protocol header and then served in various path(file, elasticsearch etc.).

Perisco use [cilium/ebpf](https://github.com/cilium/ebpf) to load [eBPF](https://ebpf.io/) program.

## Requires

- Ubuntu(kernel version > 5.15.0)

## Support Protocol

- HTTP/1.1
- MySQL
- ️HTTP/2 (⚠️unstable)

## Why Perisco?

### There is already awesome project(cilium) as a network monitoring solution in k8s

`cilium-hubble` 모니터링 솔루션은 k8s cni로 cilium-cni를 사용하는 것을 전제로 합니다. Perisco 프로젝트는 특정한 cni에 종속되지 않는 독립적인 모니터링 솔루션을 제공하는 것을 목표로 합니다. 

### What is the difference from pixie?

같은 방식(eBPF 활용)으로 4계층 패킷을 읽어서 파싱하는 pixie 프로젝트가 이미 존재합니다. pixie는 암호화된 프로토콜인 http2, gRPC를 지원하기 위해 4계층이 아닌 7계층(uprobe)를 트레이싱하는 우회기법을 사용하고, 프로토콜의 바디도 파싱하기 위해 페이로드를 최대 30KiB 까지 복사합니다. Perisco 프로젝트는 암호화된 패킷은 깔끔하게 포기해서 간결한 구조를 유지하고, 프로토콜의 헤더만을 파싱하기 때문에 페이로드를 최대 4KiB만 복사하는 등의 차이가 있습니다.

Perisco는 ingress에만 암호화를 사용하고 클러스터 내부 파드간 통신은 암호화를 사용하지 않는 사용 사례를 전제로 합니다. 암호화 계층이 내장되어있는 HTTP/2(+gRPC)의 경우, http2는 h2c(HTTP2 Cleartext), gRPC는 `insecure.NewCredentials()` 옵션을 사용하는 서비스만 추적할 수 있습니다.

## Get Started

Currently, Perisco is tested for Minikube, Google Kubernetes Engine.

GKE requires `Standard Cluster` and `ubuntu-containerd` node image.

### Install Perisco with Elasticsearch and Grafana

```shell
$ cd ./install/perisco-helm
# config values.yaml(cidrs, protocols...)
$ helm install perisco . --create-namespace -n perisco-system
```

### Install Sample Microservice

[booksapp github repo](https://github.com/BuoyantIO/booksapp)

<img alt="booksapp service map" src="https://github.com/BuoyantIO/booksapp/raw/main/images/topo.png">

```shell
$ cd ./testing/k8s
$ kubectl apply -f mysql-booksapp.yml
```

### Enter Grafana Dashboard

https://github.com/KumKeeHyun/perisco/assets/44857109/3e6ee8c2-3bc9-4e70-b334-f95474e97ee2

<img width="613" alt="dashboard1" src="https://github.com/KumKeeHyun/perisco/assets/44857109/7ebcac6f-8145-4bc6-a4c5-079b1f105ede">
<img width="613" alt="dashboard2" src="https://github.com/KumKeeHyun/perisco/assets/44857109/dd5e129f-3cf0-4d31-a8cc-8a9e1656244b">
<img width="612" alt="dashboard3" src="https://github.com/KumKeeHyun/perisco/assets/44857109/2e60ea87-0d13-4fcc-8283-a3abcb919f79">

## Architecture

Perisco-agent는 DaemonSet을 통해 클러스터에 배포된 후, bpf 프로그램을 커널에 로드해서 Pod CIDR 범위의 소켓 송수신 페이로드를 캡처합니다.

<img width="1312" alt="perisco architecture" src="https://github.com/KumKeeHyun/perisco/assets/44857109/03b712a0-3183-46ce-ac63-31be6238a93f">

응용 프로그램은 캡처한 페이로드를 7계층 프로토콜로 파싱해서 네트워크 로그를 생성하는 작업을 수행합니다. 생성한 데이터는 저장을 위해 파일, 엘라스틱서치, 카프카(TODO) 등의 저장소로 전달합니다.

<img width="1602" alt="perisco agent" src="https://github.com/KumKeeHyun/perisco/assets/44857109/11bc0023-8ce4-4738-85c0-7d65e243b3bf">

### eBPF

<img alt="bpf map" src="https://user-images.githubusercontent.com/44857109/236674728-37ffdf68-19b2-4d89-9710-8c3530bb3b77.png">

Pixie는 `write`, `read`, `send`, `recv` 등의 system call을 추적하는 반면, Perisco는 불필요한 Hook 실행을 최소화하기 위해`inet_accept`, `sock_sendmsg`, `sock_recvmsg` 커널 함수를 추적합니다.

소켓 송수신 이벤트는 Kubernetes의 NAT(service ip -> pod ip) 환경을 고려하여 Remote 소켓만 추적 대상으로 삼으며, `inet_accept` Hook을 통해 Remote 소켓 목록을 관리합니다.

### Parser

<img width="1285" alt="parser" src="https://github.com/KumKeeHyun/perisco/assets/44857109/e156e44d-fd2d-4114-a50b-b70230c50dba">

Parser는 캡처한 페이로드를 7계층 프로토콜로 파싱하는 역할을 담당하고, 동시에 아직 지원하지 않는 프로토콜이나 암호화된 프로토콜을 사용하는 소켓을 차단하는 역할도 담당합니다.

프로토콜 정보가 없는 페이로드의 경우에 unknown parser를 통해 모든 프로토콜로 파싱을 시도해보고

- 만약 성공한다면 이후에 수집된 데이터부터는 해당 프로토콜로 파싱
- 반대로 계속해서 파싱에 실패한다면 해당 서버의 송수신 이벤트는 차단

하는 구조입니다.

### Matcher
<img width="1019" alt="matcher" src="https://github.com/KumKeeHyun/perisco/assets/44857109/2ca0a00e-8614-48bb-8be8-437c8445d140">

Matcher는 Parser에서 개별로 생성된 요청/응답 헤더를 하나의 네트워크 로그로 합쳐주는 역할을 담당합니다.

