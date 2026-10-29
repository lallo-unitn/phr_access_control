FROM python:3.9-bookworm
ARG CHARM_REF=v0.60
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates libgmp-dev libssl-dev flex bison \
        autoconf autoconf-archive automake libtool \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/blynn/pbc.git /tmp/pbc \
    && cd /tmp/pbc && autoreconf -i && ./configure && make -j"$(nproc)" && make install \
    && ldconfig && rm -rf /tmp/pbc
RUN pip install --no-cache-dir setuptools wheel pyparsing \
    && git clone --branch ${CHARM_REF} --depth 1 https://github.com/JHUISI/charm.git /opt/charm \
    && cd /opt/charm && ./configure.sh && make && make install && ldconfig
RUN pip install --no-cache-dir "django~=4.2.16" requests
WORKDIR /app
EXPOSE 8000
CMD ["bash"]
