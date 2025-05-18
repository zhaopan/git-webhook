FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
#RUN go mod download
COPY vendor ./vendor 
COPY . .

RUN go build -o webhook-handler -mod=vendor

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache git

COPY --from=builder /app/webhook-handler /app/webhook-handler 
COPY --from=builder /app/vendor /app/vendor 
COPY .env /app/.env
COPY config.json /app/config.json

CMD ["/app/webhook-handler"]
