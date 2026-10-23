FROM semgrep/semgrep@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b
COPY wrapper.py /opt/platform/wrapper.py
COPY rules.yaml /opt/platform/rules.yaml
WORKDIR /work
USER 10001:10001
ENTRYPOINT ["/usr/bin/python3", "/opt/platform/wrapper.py", "semgrep"]
