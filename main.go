package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/elazarl/goproxy"
	"github.com/orbit-online/step-plugin-kmsproxy/listeners"
	"github.com/smallstep/cli-utils/step"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"

	// KMS modules (https://github.com/smallstep/step-kms-plugin/blob/3be48fd238cdc1d40dfad5e6410cf852544c3b4f/main.go#L19-L29)
	_ "go.step.sm/crypto/kms/awskms"
	_ "go.step.sm/crypto/kms/azurekms"
	_ "go.step.sm/crypto/kms/capi"
	_ "go.step.sm/crypto/kms/cloudkms"
	_ "go.step.sm/crypto/kms/mackms"
	_ "go.step.sm/crypto/kms/pkcs11"
	_ "go.step.sm/crypto/kms/softkms"
	_ "go.step.sm/crypto/kms/sshagentkms"
	_ "go.step.sm/crypto/kms/tpmkms"
	_ "go.step.sm/crypto/kms/yubikey"
)

var cli struct {
	KMSURI             string   `required:"" arg:"" name:"kmsuri" help:"Smallstep KMS key URI to use for mTLS connections"`
	CACerts            []string `name:"cacert" help:"CA bundle to trust beyond the system trust store." type:"path"`
	InsecureSkipVerify bool     `help:"Disable validation of the server certificates"`
	Listen             string   `help:"Listening address (unix:<PATH>, tcp:<HOSTNAME>:<PORT>, or systemd:)" default:"tcp:localhost:8080"`
	Verbose            bool     `help:"Turn on verbose logging"`
}

func main() {
	kong.Parse(&cli, kong.Name("step-plugin-kmsproxy"), kong.Description("Use smallstep to create mTLS tunnels"))
	err := startProxy(context.Background(), cli.KMSURI, cli.CACerts, cli.Listen, cli.InsecureSkipVerify, cli.Verbose)
	if err != nil {
		log.Fatal(err)
	}
}

func startProxy(ctx context.Context, kuri string, cacertPaths []string, listenAddrStr string, insecureSkipVerify bool, verbose bool) error {
	var err error
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("Unable to load system certificates: %w", err)
	}
	for _, cacertPath := range cacertPaths {
		raw, err := os.ReadFile(cacertPath)
		if err != nil {
			return fmt.Errorf("Failed to load cacert at %s: %w", cacertPath, err)
		}
		ok := caCertPool.AppendCertsFromPEM(raw)
		if !ok {
			return fmt.Errorf("Failed to append %s to the certificate store", cacertPath)
		}
	}

	// Test loading
	_, err = loadCert(ctx, kuri)
	if err != nil {
		return fmt.Errorf("Failed to load client certificate: %w", err)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = verbose
	proxy.AllowHTTP2 = true
	proxy.OnRequest().DoFunc(func(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		req.URL.Scheme = "https"
		proxyCtx.Proxy.Tr.TLSClientConfig = &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return loadCert(ctx, kuri)
			},
			Renegotiation:      tls.RenegotiateFreelyAsClient,
			RootCAs:            caCertPool,
			InsecureSkipVerify: insecureSkipVerify,
		}
		return req, nil
	})

	proto, addr, found := strings.Cut(listenAddrStr, ":")
	if !found {
		return fmt.Errorf("Unable to determine listening method in --listen option, expected <PROTO>:<ADDR>, got %s", listenAddrStr)
	}

	listener, err := listeners.CreateListener(proto, addr)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: http.HandlerFunc(proxy.ServeHTTP)}
	fmt.Println("Startup completed")
	go server.Serve(listener)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
	_ = <-c
	return err
}

func loadCert(ctx context.Context, kuri string) (*tls.Certificate, error) {
	km, err := openKMS(ctx, kuri)
	if err != nil {
		return nil, fmt.Errorf("Unable to open KMS using URI %s: %w", kuri, err)
	}
	cm, ok := km.(apiv1.CertificateChainManager)
	if !ok {
		return nil, fmt.Errorf("Unable to load certificates from KMS: %s", km)
	}
	var clientCerts [][]byte
	certs, err := cm.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
		Name: kuri,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to load certificates from KMS URI %s: %w", kuri, err)
	}
	for _, c := range certs {
		clientCerts = append(clientCerts, c.Raw)
	}
	key, err := km.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: kuri,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to load private key using KMS URI %s: %w", kuri, err)
	}
	return &tls.Certificate{
		Certificate: clientCerts,
		PrivateKey:  key,
	}, nil
}

// Source: https://github.com/smallstep/step-kms-plugin/blob/3be48fd238cdc1d40dfad5e6410cf852544c3b4f/cmd/root.go#L74-L94
func openKMS(ctx context.Context, kuri string) (apiv1.KeyManager, error) {
	typ, err := apiv1.TypeOf(kuri)
	if err != nil {
		return nil, err
	}

	var storageDirectory string
	if typ == apiv1.TPMKMS {
		if err := step.Init(); err != nil {
			return nil, err
		}
		storageDirectory = filepath.Join(step.Path(), "tpm")
	}

	// Type is not necessary, but it avoids an extra validation
	return kms.New(ctx, apiv1.Options{
		Type:             typ,
		URI:              kuri,
		StorageDirectory: storageDirectory,
	})
}
