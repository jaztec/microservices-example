FROM golang:1.16-buster as builder
LABEL maintainer="Jasper van Herpt <jasper@omines.com>"

# Create user for the app
RUN useradd -ms /bin/bash app-user

ENV GO111MODULE=on

WORKDIR /opt/local
COPY . .

RUN apt update && apt install --yes git make ca-certificates && update-ca-certificates

RUN make build

FROM debian:buster-slim AS auth_service

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

COPY --from=builder /opt/local/bin/auth_service /usr/bin/app

RUN mkdir -p /var/log/app \
    && chown -R app-user /var/log/app

USER app-user

CMD ["/usr/bin/app"]

FROM debian:buster-slim AS client_service

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

COPY --from=builder /opt/local/bin/client_service /usr/bin/app

RUN mkdir -p /var/log/app \
    && chown -R app-user /var/log/app

USER app-user

CMD ["/usr/bin/app"]

FROM debian:buster-slim AS user_service

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

COPY --from=builder /opt/local/bin/user_service /usr/bin/app

RUN mkdir -p /var/log/app \
    && chown -R app-user /var/log/app

USER app-user

CMD ["/usr/bin/app"]

FROM debian:buster-slim AS ca_service

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

COPY --from=builder /opt/local/bin/ca_service /usr/bin/app

RUN mkdir -p /var/log/app \
    && chown -R app-user /var/log/app

USER app-user

CMD ["/usr/bin/app"]