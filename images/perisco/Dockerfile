FROM golang:1.18.5-alpine AS builder

RUN apk add --update make

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build
COPY . .

# RUN go mod download
WORKDIR /build/perisco
RUN make bin-only

WORKDIR /dist
RUN cp /build/perisco/perisco .

FROM alpine:latest
COPY --from=builder /dist/perisco .

ENTRYPOINT ["/perisco", "run"]