FROM python@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd -g 10001 hveritas && \
    useradd -u 10001 -g 10001 -d /tmp -s /usr/sbin/nologin -M hveritas && \
    pip install \
        pytest==8.3.4 \
        ruff==0.8.4 \
        mypy==1.13.0 \
        jsonschema==4.23.0

USER 10001:10001
WORKDIR /tmp
