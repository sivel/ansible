FROM ubuntu:xenial

RUN apt-get update && apt-get install -y \
    python3-docutils \
    cdbs \
    debootstrap \
    devscripts \
    make \
    pbuilder \
    python3-jinja2 \
    python3-setuptools \
    python3-yaml \
    python3-packaging \
    locales \
    && \
    apt-get clean
    && sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

VOLUME /ansible
WORKDIR /ansible

#ENTRYPOINT ["/bin/bash", "-c"]
CMD ["make", "-f", "/ansible/Makefile", "PYTHON=python3", "deb"]
