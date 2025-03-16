#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Start Docker Compose
echo "Starting Docker Compose..."
docker-compose build
docker-compose up -d
docker exec -it server-10.9.0.5 ./attack_detection/attack_detect 10
docker-compose down

