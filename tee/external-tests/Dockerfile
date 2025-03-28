FROM ghcr.io/nixos/nix AS builder

# Pin nixpkgs.
ARG NIXPKGS="nixpkgs/73cf49b8ad837ade2de76f87eb53fc85ed5d4680"

# Create some files and directories needed by the build.
RUN mkdir -p /build/bin/ /build/build/ /build/tmp/ /build/etc && \
    chmod 777 /build/tmp/ && \
    echo "root:x:0:0:System administrator:/root:/bin/sh" > /build/etc/passwd && \
    echo "nixbld:x:1000:1000::/homeless-shelter:/bin/sh" >> /build/etc/passwd && \
    echo "root:x:0:" > /build/etc/group && \
    echo "users:x:1000:" >> /build/etc/group && \
    echo "127.0.0.1 localhost" > /build/etc/hosts && \
    echo "::1 localhost" >> /build/etc/hosts

# Enable nix flakes and install bash into the store.
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf && \
    nix copy --to "/build" ${NIXPKGS}#bash && \
    ln -s $(nix eval --raw ${NIXPKGS}#bash)/bin/sh /build/bin/sh

# Copy all inputs into the store and create a dev-env.
ARG PACKAGE
# nix print-dev-env will reference the CWD.
WORKDIR "/build/"
RUN nix copy --to "/build" --no-check-sigs ${NIXPKGS}#${PACKAGE}.inputDerivation && \
    nix print-dev-env ${NIXPKGS}#${PACKAGE} > /build/build/dev-env

# Copy all files.
FROM scratch
COPY --from=builder --chown=1000:1000 /build /
WORKDIR "/build/"
USER 1000:1000
# This entrypoint is not used by mushroom. It's only used when the container executed with docker.
ENTRYPOINT ["/bin/sh", "-c", "source /build/dev-env && set -e && dontInstall=1 && dontFixup=1 && genericBuild"]
