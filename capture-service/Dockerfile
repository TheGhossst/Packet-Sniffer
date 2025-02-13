FROM golang:1.21

WORKDIR /app

# Install libpcap-dev for packet capture
RUN apt-get update && apt-get install -y libpcap-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o main .

CMD ["./main"] 