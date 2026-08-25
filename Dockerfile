FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /pratu ./cmd/pratu

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 pratu
USER pratu
COPY --from=build /pratu /usr/local/bin/pratu
EXPOSE 4433 4434
ENTRYPOINT ["pratu"]
CMD ["serve"]
