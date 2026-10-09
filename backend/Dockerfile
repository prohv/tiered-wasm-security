FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /backend .

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /backend /app/backend
EXPOSE 8081
CMD ["/app/backend"]
