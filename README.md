# Execsnoop-K8s

Log all binary executions in Kubernetes.

Based on BPF program from [iovisor/gobpf](https://github.com/iovisor/gobpf/blob/2289761f1e2092a7416cd5fd55a218802d997cb6/examples/bcc/execsnoop/execsnoop.go).

Development WIP.

## Build

1. Install `https://github.com/iovisor/bcc`
([INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md))

2. Build on host machine:

   ```bash
   go build execsnoop.go
   ```

3. Dockerize

   ```bash
   docker build -t execsnoop .
   ```

## Run in Docker

```bash
sudo docker run --rm -it -v /lib:/lib -v /usr/src:/usr/src -v /var/run/docker.sock:/var/run/docker.sock --privileged execsnoop
```

## Run in Kubernetes

TBD
