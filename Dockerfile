# Use the official Go image as the base image
FROM golang:1.23

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files to download dependencies
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod tidy

# Copy the entire application code to the working directory
COPY . .

# Build the Go application
RUN go build -o main ./cmd

# Expose the port the application runs on
EXPOSE 8080

# Command to run the application
CMD ["./main"]
