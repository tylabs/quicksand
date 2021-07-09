FROM lambci/lambda:build-python3.8

LABEL maintainer "tylabs"

# Install Yara
COPY . /quicksand
WORKDIR /quicksand
RUN yum -y install automake libtool make gcc pkg-config openssl-devel wget jansson-devel file-devel git

# Install quicksand
RUN pip install --upgrade quicksand -t /quicksand/pip  
RUN cd /quicksand/pip
RUN rm -r *.dist-info *.egg-info ; exit 0
RUN find . -name __pycache__ | xargs rm -r ; exit 0
RUN mv _cffi_backend.cpython-36m-x86_64-linux-gnu.so _cffi_backend.so ; exit 0
RUN cd /quicksand/; exit 0
RUN mkdir lambda; exit 0
RUN cp /quicksand/pip/.libs_cffi_backend/* lambda; exit 0
RUN cp -r pip/* lambda; exit 0

# yara / openssl
RUN cp /usr/lib64/linux-vdso.so.1 lambda; exit 0
RUN cp /usr/lib64/libgssapi_krb5.so.2 lambda; exit 0
RUN cp /usr/lib64/libkrb5.so.3 lambda; exit 0
RUN cp /usr/lib64/libcom_err.so.2 lambda; exit 0
RUN cp /usr/lib64/libk5crypto.so.3 lambda; exit 0
RUN cp /usr/lib64/libcrypto.so.10 lambda; exit 0
RUN cp /usr/lib64/libdl.so.2 lambda; exit 0
RUN cp /usr/lib64/libz.so.1 lambda; exit 0
RUN cp /usr/lib64/libc.so.6 lambda; exit 0
RUN cp /usr/lib64/libkrb5support.so.0 lambda; exit 0
RUN cp /usr/lib64/libkeyutils.so.1 lambda; exit 0
RUN cp /usr/lib64/libresolv.so.2 lambda; exit 0
RUN cp /usr/lib64/libpthread.so.0 lambda; exit 0
RUN cp /usr/lib64/ld-linux-x86-64.so.2 lambda; exit 0
RUN cp /usr/lib64/libselinux.so.1 lambda; exit 0
RUN cp /usr/lib64/libpcre.so.1 lambda; exit 0
RUN cp /usr/lib64/ld-linux-x86-64.so.2 lambda; exit 0
RUN cp /usr/lib64/libssl.so lambda; exit 0
RUN cp /usr/lib64/libpcre.so lambda; exit 0

# pdfs
RUN cp /lib64/libbz2.so.1 lambda; exit 0
RUN cp /lib64/libcrypt.so.1 lambda; exit 0
RUN cp /lib64/libexpat.so.1 lambda; exit 0
RUN cp /lib64/libfreebl3.so lambda; exit 0
RUN cp /lib64/libkeyutils.so.1 lambda; exit 0
RUN cp /lib64/libm.so.6 lambda; exit 0
RUN cp /lib64/librt.so.1 lambda; exit 0
RUN cp /lib64/libssl.so.10 lambda; exit 0
RUN cp /lib64/libutil.so.1 lambda; exit 0
RUN cp /usr/lib64/libcom_err.so.2 lambda; exit 0
RUN cp /usr/lib64/libffi.so.6 lambda; exit 0
RUN cp /usr/lib64/libgssapi_krb5.so.2 lambda; exit 0
RUN cp /usr/lib64/libk5crypto.so.3 lambda; exit 0
RUN cp /usr/lib64/libkrb5.so.3 lambda; exit 0
RUN cp /usr/lib64/libkrb5support.so.0 lambda; exit 0
RUN cp /usr/lib64/liblzma.so.5 lambda; exit 0



RUN cd lambda; exit 0

# copy all the dependencies to a zip
RUN zip -r dependencies.zip lambda/* ; exit 0
CMD python wait.py

#### Building a Yara-Python Lambda Docker image
## docker build -t quicksand .
## docker run -d quicksand 
## docker exec -it <docker_id> /quicksand/pip/bin/quicksand <malware_file>
## docker exec -it <docker_id> /bin/bash

### Extracting Python etc:
## mkdir ./quicksand/build
## docker cp <docker_id>:/quicksand/dependencies.zip .

## Then add your own lambda_function.py code and upload the zip to Lambda


