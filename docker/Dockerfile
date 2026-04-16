FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nftables \
    iproute2 \
    openssl \
    procps \
    conntrack \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/minifw_ai

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# enforce.py calls ["nft", ...] — add /usr/sbin after pip install so
# /usr/local/bin (python, pip) is not wiped during the install step
ENV PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY app/     ./app/
COPY config/  ./config/
COPY scripts/ ./scripts/

RUN mkdir -p models
COPY models/mlp_model.pkl ./models/

# Sector YARA rules — test_rules.yar excluded to avoid spurious matches
RUN mkdir -p yara_rules
COPY yara_rules/hospital_rules.yar ./yara_rules/
COPY yara_rules/sme_rules.yar      ./yara_rules/

COPY docker/entrypoint-engine.sh ./docker/entrypoint-engine.sh
COPY docker/entrypoint-web.sh    ./docker/entrypoint-web.sh
RUN chmod +x docker/entrypoint-engine.sh docker/entrypoint-web.sh

RUN mkdir -p logs tls

ENV PYTHONPATH=/opt/minifw_ai/app
