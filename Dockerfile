# Stage 1: Build the Go application
FROM golang:1.25.2-alpine3.21 AS build

WORKDIR /app

# Copy Go modules and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build the application
RUN go build -o /api-gateway ./cmd/gateway


# Stage 2: Create the final, lightweight image
FROM alpine:latest

WORKDIR /

# Copy the built binary from the build stage
COPY --from=build /api-gateway /api-gateway

# Copy the configuration file
COPY config.yaml /config.yaml

# Expose the port the gateway will run on
EXPOSE 8080

# The command to run the application
CMD [ "/api-gateway" ]
