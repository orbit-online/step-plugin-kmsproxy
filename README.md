# step-plugin-kmsproxy

This mTLS proxy was inspired by [this blogpost](https://medium.com/@piyifan123/use-yubikey-to-secure-kubernetes-authentication-client-cert-8978c04a2b90)
by @piyifan123. The associated [repository](https://github.com/piyifan123/kubectl-yubikey-proxy) has been forked mainly
for attribution purposes (barely any code is shared).

step-plugin-kmsproxy is a an mTLS proxy that allows you to connect to remotes
using an X.509 certificate and key that is accessible through smallstep.

The primary use case for this is Kubernetes client-authentication through any
KMS that Smallstep supports (YubiKey, SSH agent, TPM, AWS, Azure, etc.).

## Usage

_Note that the setup below assumes that you have already set up a smallstep user_
_certificate and key that can authenticate to your kubernetes cluster_

Start the proxy by specifying the Smallstep KMS URI, the target address, and
the CA certificate to trust when connecting to the target.

```sh
$ ./step-plugin-kmsproxy --cacert ~/.kube/ca.crt tpmkms:mykey https://api.kube.example.com:6443
Listening to localhost:8080
Startup completed
```

Create a [kubeconfig](example/kubeconfig.yaml) that connects to the proxy:

```yaml
# $HOME/.kube/proxy.yaml
apiVersion: v1
kind: Config
clusters:
  - cluster:
      server: http://localhost:8091
    name: example
contexts:
  - context:
      cluster: example
      namespace: default
      user: admin@example
    name: admin@example
users:
  - name: admin@example
    user:
      username: anon
current-context: admin@example
```

Now, use `kubectl` to query a resource.

```sh
$ KUBECONFIG=$HOME/.kube/proxy.yaml kubectl get ns
NAME                 STATUS   AGE
default              Active   21d
kube-node-lease      Active   21d
kube-public          Active   21d
kube-system          Active   21d
```

### With SystemD

You can also use `--listen=systemd:` to use SystemD socket activation for managing
the proxy. Take a look at the [examples](example/)
