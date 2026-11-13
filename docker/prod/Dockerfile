# base image
FROM debian:bookworm-slim

WORKDIR /app

# ca-certificates for HTTPS requests; nftables/iptables for IP banning.
# The host's binaries are not reachable from here: network_mode host shares the
# network namespace, not the filesystem, so the CLI must live in this image.
RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates sqlite3 nftables iptables && \
    rm -rf /var/lib/apt/lists/*

# copy binary and configuration files
COPY ./stackdog .
COPY ./.env .

EXPOSE 5000

ENTRYPOINT ["/app/stackdog"]
