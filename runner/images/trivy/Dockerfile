FROM aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c AS upstream
FROM python:3.12.15-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
COPY --from=upstream /usr/local/bin/trivy /usr/local/bin/trivy
COPY wrapper.py trivy.yaml secret.yaml empty.ignore /opt/platform/
WORKDIR /work
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/python", "/opt/platform/wrapper.py", "trivy"]
