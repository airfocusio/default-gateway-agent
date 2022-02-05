FROM alpine:3.15
RUN apk add --no-cache iptables
COPY default-gateway-agent /bin/default-gateway-agent
ENTRYPOINT ["/bin/default-gateway-agent"]
