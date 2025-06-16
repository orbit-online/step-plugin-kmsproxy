package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/orbit-online/step-plugin-kmsproxy/listeners"
	"github.com/smallstep/cli-utils/step"
	"github.com/spf13/cobra"
	"go.step.sm/crypto/kms"
	"go.step.sm/crypto/kms/apiv1"
)

const (
	exampleTxt = "  $ step-plugin-kmsproxy --cacert=ca.crt --listen localhost:8888 tpmkms:name=mykey https://cluster.example.com:6443"
)

func NewCmd() *cobra.Command {
	cacertPath := ""
	listenAddrStr := "tcp:localhost:8080"
	insecureSkipVerify := false

	cmd := &cobra.Command{
		Use:          "step-plugin-kmsproxy <kmsuri> <targeturi>",
		Short:        "Use smallstep to create mTLS tunnels",
		Example:      exampleTxt,
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			return startProxy(c.Context(), args[0], args[1], cacertPath, listenAddrStr, insecureSkipVerify)
		},
	}

	cmd.Flags().StringVar(&cacertPath, "cacert", cacertPath, "Path to CA bundle file (PEM/X509). Uses system trust store by default.")
	cmd.Flags().StringVarP(&listenAddrStr, "listen", "l", listenAddrStr, "Listening address (unix:<PATH>, tcp:<HOSTNAME>:<PORT>, or systemd:)")
	cmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", insecureSkipVerify, "Disable validation of the server certificate")
	return cmd
}

func startProxy(ctx context.Context, kuri string, target string, cacertPath string, listenAddrStr string, insecureSkipVerify bool) error {
	targetAddr, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("Failed to parse target URL: %w", err)
	}
	var caCertPool *x509.CertPool
	if cacertPath == "" {
		caCertPool, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("Unable to load system certificates: %w", err)
		}
	} else {
		raw, err := os.ReadFile(cacertPath)
		if err != nil {
			return fmt.Errorf("Failed to load cacert at %s: %w", cacertPath, err)
		}
		caCertPool = x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(raw)
	}

	loadCert := func() (*tls.Certificate, error) {
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

	// Test loading
	_, err = loadCert()
	if err != nil {
		return fmt.Errorf("Failed to load client certificate: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetAddr)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return loadCert()
			},
			Renegotiation:      tls.RenegotiateFreelyAsClient,
			RootCAs:            caCertPool,
			InsecureSkipVerify: insecureSkipVerify,
		},
	}

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
