FROM public.ecr.aws/amazonlinux/amazonlinux:2023

LABEL maintainer=https://github.com/tylabs
WORKDIR /app

# Install Python 3, pip, shadow-utils (for non-root user creation), and build tools if needed
RUN dnf update -y && \
    dnf install -y python3 python3-pip python3-devel gcc shadow-utils && \
    dnf clean all && \
    groupadd -g 10001 appuser && \
    useradd -u 10001 -g 10001 -M -s /sbin/nologin appuser

# Install pinned dependencies into /app
RUN python3 -m pip install --no-cache-dir "quicksand>=2.3.3,<3.0.0" "boto3>=1.34.0,<2.0.0" -t /app

# Copy Lambda function code as root-owned, world-readable
COPY --chown=0:0 functions/*.py /app/
RUN chmod -R a+rX /app

ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001

# Set the entrypoint (adjust if your handler is in a different file/function)
CMD ["lambda_function.lambda_handler"]
