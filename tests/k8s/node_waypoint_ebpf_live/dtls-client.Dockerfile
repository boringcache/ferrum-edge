# DTLS live-gate client. openssl is installed HERE, on the runner that has
# outbound internet, then the image is loaded into kind. The probe pods are
# mesh-enrolled: connect4 rewrites their TCP connect() to the capture listener,
# so `apk add openssl` from inside the pod cannot reach Alpine mirrors.
FROM python:3.12-alpine
RUN apk add --no-cache openssl
CMD ["sh", "-c", "sleep 365d"]
