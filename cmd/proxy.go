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
	"path/filepath"

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
	listenAddrStr := "localhost:8080"

	cmd := &cobra.Command{
		Use:          "step-plugin-kmsproxy <kmsuri> <targeturi>",
		Short:        "Use smallstep to create mTLS tunnels",
		Example:      exampleTxt,
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(c *cobra.Command, args []string) error {
			return startProxy(c.Context(), args[0], args[1], cacertPath, listenAddrStr)
		},
	}

	cmd.Flags().StringVar(&cacertPath, "cacert", cacertPath, "Path to CA bundle file (PEM/X509). Uses system trust store by default.")
	cmd.Flags().StringVarP(&listenAddrStr, "listen", "l", listenAddrStr, "Listen address")
	return cmd
}

func startProxy(ctx context.Context, kuri string, target string, cacertPath string, listenAddrStr string) error {
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

	km, err := openKMS(ctx, kuri)
	if err != nil {
		return fmt.Errorf("Unable to open KMS using URI %s: %w", kuri, err)
	}
	cm, ok := km.(apiv1.CertificateChainManager)
	if !ok {
		return fmt.Errorf("Unable to load certificates from KMS: %w", km)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetAddr)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
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
			},
			RootCAs: caCertPool,
		},
	}

	server := &http.Server{
		Addr:    listenAddrStr,
		Handler: http.HandlerFunc(proxy.ServeHTTP),
	}

	fmt.Printf("Proxy running on %s\n", listenAddrStr)
	return server.ListenAndServe()
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
