# syntax=docker/dockerfile:1.3-labs

FROM rustlang/rust:nightly-slim as builder
COPY . /
WORKDIR /
COPY --from=alpine:latest  /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
RUN <<-EOF
apt-get update -y
apt-get install lsb-release software-properties-common gnupg -y
apt-get install -y build-essential \
     pkg-config \
     libssl-dev \
     wget \
     git
bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
git submodule update --init --recursive
cargo build -r -p spectre-prover
EOF

FROM debian:stable
ENV RUST_BACKTRACE=full
WORKDIR /
COPY /lightclient-circuits/config/ /lightclient-circuits/config/
COPY --from=builder /target/release/spectre-prover-cli /spectre-prover-cli
RUN <<-EOF
apt-get update -y
apt-get install libssl-dev -y
chmod +x /spectre-prover-cli
mkdir -p /build /params
EOF
ENTRYPOINT ["./spectre-prover-cli", "rpc", "--port", "3000"]
CMD ["--spec", "testnet"]
