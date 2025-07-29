# Билд стадии
FROM golang:1.23.11-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /medods

FROM alpine:latest

WORKDIR /app

# Копируем бинарник и миграции
COPY --from=builder /medods .
# COPY migrations ./migrations

# Копируем конфиги (если есть)
# COPY config.yaml .

# Указываем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./medods"]