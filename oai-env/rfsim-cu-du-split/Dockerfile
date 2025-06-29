FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    tcpdump \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ./script/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

CMD ["tail", "-f", "/dev/null"]
