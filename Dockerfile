FROM python:3.11.11-slim

ARG TERRAFORM_VERSION=1.9.8
ARG CHECKOV_VERSION=3.2.504

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git unzip bash && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/terraform.zip https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    unzip /tmp/terraform.zip -d /usr/local/bin && rm /tmp/terraform.zip

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
RUN pip install --no-cache-dir checkov==${CHECKOV_VERSION}

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
