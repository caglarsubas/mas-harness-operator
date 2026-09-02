FROM scratch
ARG TARGETARCH
COPY bin/operator-${TARGETARCH} /operator
USER 65532:65532
ENTRYPOINT ["/operator"]
