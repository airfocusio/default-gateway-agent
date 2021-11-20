FROM scratch
ENTRYPOINT ["/bin/default-gateway-agent"]
COPY default-gateway-agent /bin/default-gateway-agent
