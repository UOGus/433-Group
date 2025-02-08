FROM python:3.13.1

# Set the working directory in the container
WORKDIR /server

# Copy the packages.txt from the docker directory into the container
COPY ./packages.txt /server/

# Install dependencies from the packages.txt
RUN pip install -r /server/packages.txt

# Run the server
CMD ["python", "/server/server.py"]