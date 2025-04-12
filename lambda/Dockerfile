FROM public.ecr.aws/amazonlinux/amazonlinux:2023

LABEL maintainer=https://github.com/tylabs
WORKDIR /

# Install necessary build tools, wget, and openssl-devel
RUN yum update -y && yum groupinstall -y "Development Tools" && yum install -y wget openssl-devel zlib-devel libffi-devel libarchive-devel bzip2-devel libuuid-devel

# Download and install Python 3.13
RUN wget https://www.python.org/ftp/python/3.13.0/Python-3.13.0.tgz
RUN tar -xvf Python-3.13.0.tgz
WORKDIR Python-3.13.0
RUN ./configure --enable-optimizations
RUN make -j $(nproc)
RUN make install

# Verify Python installation
RUN python3.13 --version

# Install pip
RUN curl -O https://bootstrap.pypa.io/get-pip.py
RUN python3.13 get-pip.py

# Set working directory and copy application files
WORKDIR /app

# Copy your requirements file
COPY /quicksand/requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt -t .

# Copy your Lambda function code
COPY *.py .

# Set the entrypoint (adjust if your handler is in a different file/function)
#CMD ["lambda_function.handler"]
#CMD python wait.py
CMD ["sleep", "infinity"]