FROM lambci/lambda:build-python3.8

LABEL maintainer "tylabs"

ENV YARA 4.0.5

# Install Yara
RUN yum -y install automake libtool make gcc pkg-config openssl-devel wget jansson-devel file-devel git
#RUN echo "===> Install Yara-Python from source..." \
#  && cd /tmp \
#  && git clone --recursive https://github.com/VirusTotal/yara-python \
#  && cd yara-python \
#  && python setup.py build \
#  && python setup.py install \
#  && rm -rf /tmp/*

COPY . /quicksand
# Install quicksand
WORKDIR /quicksand
RUN pip install --upgrade -r requirements.txt -t /quicksand/pip
RUN cd /quicksand/pip
RUN rm -r *.dist-info *.egg-info ; exit 0
RUN find . -name __pycache__ | xargs rm -r ; exit 0
RUN mv _cffi_backend.cpython-36m-x86_64-linux-gnu.so _cffi_backend.so ; exit 0
RUN cd cryptography/hazmat/bindings ; exit 0
RUN mv _constant_time.abi3.so _constant_time.so; exit 0
RUN mv _openssl.abi3.so _openssl.so; exit 0
RUN mv _padding.abi3.so _padding.so; exit 0
RUN cd /quicksand/; exit 0
RUN mkdir lambda; exit 0
RUN cp /quicksand/pip/.libs_cffi_backend/* lambda; exit 0
RUN cp -r pip/* lambda; exit 0
RUN cp /usr/bin/pdftotext lambda; exit 0
RUN cp /usr/lib64/libarchive.so.13 lambda; exit 0
RUN cp /usr/lib64/libfontconfig.so.1 lambda; exit 0
RUN cp /usr/lib64/libfreetype.so.6 lambda; exit 0
RUN cp /usr/lib64/libjbig.so.2.0 lambda; exit 0
RUN cp /usr/lib64/libjpeg.so.62 lambda; exit 0
RUN cp /usr/lib64/liblcms2.so.2 lambda; exit 0
RUN cp /usr/lib64/liblzma.so.5 lambda; exit 0
RUN cp /usr/lib64/liblzo2.so.2 lambda; exit 0
RUN cp /usr/lib64/libopenjpeg.so.2 lambda; exit 0
RUN cp /usr/lib64/libpcrecpp.so.0 lambda; exit 0
RUN cp /usr/lib64/libpng12.so.0 lambda; exit 0
RUN cp /usr/lib64/libpoppler.so.46 lambda; exit 0
RUN cp /usr/lib64/libstdc++.so.6 lambda; exit 0
RUN cp /usr/lib64/libtiff.so.5 lambda; exit 0
RUN cp /usr/lib64/libxml2.so.2 lambda; exit 0
RUN cp /usr/local/lib/libyara.so.3 lambda; exit 0
RUN cp /usr/lib64/libatomic.so.1 lambda; exit 0
RUN cp /usr/lib64/libcilkrts.so.5 lambda; exit 0
RUN cp /usr/lib64/libcom_err.so lambda; exit 0
RUN cp /usr/lib64/libcrypto.so lambda; exit 0
RUN cp /usr/lib64/libcrypto.so.10 lambda; exit 0
RUN cp /usr/lib64/libgcc_s.so.1 lambda; exit 0
RUN cp /usr/lib64/libgomp.so.1 lambda; exit 0
RUN cp /usr/lib64/libgssapi_krb5.so lambda; exit 0
RUN cp /usr/lib64/libgssrpc.so lambda; exit 0
RUN cp /usr/lib64/libidn.so.11 lambda; exit 0
RUN cp /usr/lib64/libitm.so.1 lambda; exit 0
RUN cp /usr/lib64/libjansson.so lambda; exit 0
RUN cp /usr/lib64/libjansson.so.4 lambda; exit 0
RUN cp /usr/lib64/libk5crypto.so lambda; exit 0
RUN cp /usr/lib64/libkadm5clnt_mit.so lambda; exit 0
RUN cp /usr/lib64/libkadm5clnt_mit.so.11 lambda; exit 0
RUN cp /usr/lib64/libkadm5clnt.so lambda; exit 0
RUN cp /usr/lib64/libkadm5srv_mit.so lambda; exit 0
RUN cp /usr/lib64/libkadm5srv_mit.so.11 lambda; exit 0
RUN cp /usr/lib64/libkadm5srv.so lambda; exit 0
RUN cp /usr/lib64/libkdb5.so lambda; exit 0
RUN cp /usr/lib64/libkeyutils.so lambda; exit 0
RUN cp /usr/lib64/libkrad.so lambda; exit 0
RUN cp /usr/lib64/libkrb5.so lambda; exit 0
RUN cp /usr/lib64/libkrb5support.so lambda; exit 0
RUN cp /usr/lib64/liblsan.so.0 lambda; exit 0
RUN cp /usr/lib64/libmagic.so lambda; exit 0
RUN cp /usr/lib64/libmpx.so.2 lambda; exit 0
RUN cp /usr/lib64/libmpxwrappers.so.2 lambda; exit 0
RUN cp /usr/lib64/libpcre16.so lambda; exit 0
RUN cp /usr/lib64/libpcre32.so lambda; exit 0
RUN cp /usr/lib64/libpcrecpp.so lambda; exit 0
RUN cp /usr/lib64/libpcreposix.so lambda; exit 0
RUN cp /usr/lib64/libpcre.so lambda; exit 0
RUN cp /usr/lib64/libquadmath.so.0 lambda; exit 0
RUN cp /usr/lib64/libselinux.so lambda; exit 0
RUN cp /usr/lib64/libsepol.so lambda; exit 0
RUN cp /usr/lib64/libssl.so lambda; exit 0
RUN cp /usr/lib64/libssl.so.10 lambda; exit 0
RUN cp /usr/lib64/libstdc++.so.6 lambda; exit 0
RUN cp /usr/lib64/libtsan.so.0 lambda; exit 0
RUN cp /usr/lib64/libubsan.so.0 lambda; exit 0
RUN cp /usr/lib64/libverto.so lambda; exit 0
RUN cp /usr/lib64/pkgconfig lambda; exit 0

RUN mv lambda/yara.cpython-36m-x86_64-linux-gnu.so lambda/yara.so; exit 0
RUN cd lambda; exit 0
RUN zip -r dependencies.zip * ; exit 0
CMD python wait.py

#### Building a Yara-Python Lambda Docker image
## docker build -t quicksand .
## docker run -d quicksand 
## docker exec -it <docker_id> python quicksand.py <malware_file>
## docker exec -it <docker_id> /bin/bash

### Extracting Python etc:
## mkdir /quicksand/build
## docker cp <docker_id>:/quicksand/dependencies.zip .


