FROM golang:1.23.1 AS builder

WORKDIR /app
COPY . .

RUN go mod tidy

WORKDIR /app/cmd
RUN go build -o auth .

FROM gcr.io/distroless/base

COPY --from=builder /app/cmd/auth /auth

EXPOSE 55555

CMD ["/auth"]