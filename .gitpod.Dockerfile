FROM gitpod/workspace-full
USER gitpod
RUN go env -w GOPRIVATE=github.com/da-moon
RUN curl -fsSL \
    https://raw.githubusercontent.com/da-moon/core-utils/master/bin/fast-apt | sudo bash -s -- \
    --init || true;
