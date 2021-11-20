# default-gateway-agent

TODO

## Launching the agent as a DaemonSet

This repo includes an example yaml file that can be used to launch the default-gateway-agent as a DaemonSet in a Kubernetes cluster.

```
kubectl create -f default-gateway-agent.yaml
```

The spec in `default-gateway-agent.yaml` specifies the `kube-system` namespace for the DaemonSet Pods.

## Configuring the agent

TODO

```
kubectl create configmap default-gateway-agent --from-file=default-gatway-agent-config.yaml --namespace=kube-system
```

Note that we created the `ConfigMap` in the same namespace as the DaemonSet Pods, and named the `ConfigMap` to match the spec in `default-gateway-agent.yaml`. This is necessary for the `ConfigMap` to appear in the Pods' filesystems.

## Rationale

TODO

## Releasing

See [RELEASE](RELEASE.md).

## Developing

Clone the repo to `$GOPATH/src/github.com/airfocusio/default-gateway-agent`.

The build tooling is based on [thockin/go-build-template](https://github.com/thockin/go-build-template).

Run `make` or `make build` to compile the default-gateway-agent.  This will use a Docker image
to build the agent, with the current directory volume-mounted into place.  This
will store incremental state for the fastest possible build.  Run `make
all-build` to build for all architectures.

Run `make test` to run the unit tests.

Run `make container` to build the container image.  It will calculate the image
tag based on the most recent git tag, and whether the repo is "dirty" since
that tag (see `make version`).  Run `make all-container` to build containers
for all architectures.

Run `make push` to push the container image to `REGISTRY`.  Run `make all-push`
to push the container images for all architectures.

Run `make clean` to clean up.

## Kudos

This code base has been started from https://github.com/kubernetes-sigs/ip-masq-agent as base.
