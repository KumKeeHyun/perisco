FROM kbzjung359/perisco-builder:0.0.1 AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build
COPY ./go.* .
RUN go mod download

COPY . .
WORKDIR /build/perisco/bpf
RUN make generate
WORKDIR /build/perisco
RUN make bin-only

WORKDIR /dist
RUN cp /build/perisco/perisco .

FROM alpine:latest
COPY --from=builder /dist/perisco .

ENTRYPOINT ["/perisco", "start"]