FROM public.ecr.aws/amazonlinux/amazonlinux:latest

LABEL maintainer=https://github.com/tylabs
WORKDIR /app

# Install Python 3, pip, and build tools if needed by native wheels
RUN yum update -y && yum install -y python3 python3-pip python3-devel gcc && yum clean all

# Install dependencies into /app
RUN python3 -m pip install --no-cache-dir quicksand boto3 -t .

# Copy Lambda function code
COPY functions/*.py .

# Set the entrypoint (adjust if your handler is in a different file/function)
#CMD ["lambda_function.lambda_handler"]
CMD ["sleep", "infinity"]
