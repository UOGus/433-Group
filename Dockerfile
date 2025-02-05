FROM python:3.13.1
#name our working directory vnet
WORKDIR /vnet

#copy everything from . into vnet excluding files in dockerignore
COPY . /vnet

#install dependencies from packages
RUN pip install -r packages.txt

#expose the port the server is listening on
EXPOSE 8080

#run the server
CMD ["python", "./server.py"]