package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/AimTune/tenarium/pkg/client"

	tenariumv1 "github.com/AimTune/tenarium/operator/api/v1alpha1"
)

// UserAgent is sent with every API request the operator makes.
const UserAgent = "tenarium-operator/1"

// DefaultConnection is the connection used by resources without a
// spec.connectionRef. It comes from the operator's flags.
type DefaultConnection struct {
	// URL of the Tenarium server; empty disables the default connection.
	URL string
	// APIKey is used as is when set.
	APIKey string
	// SecretNamespace/SecretName/SecretKey select the API key when APIKey
	// is empty.
	SecretNamespace string
	SecretName      string
	SecretKey       string
}

// errNoConnection is returned when a resource has no connectionRef and the
// operator has no default connection.
var errNoConnection = errors.New("no connectionRef set and the operator has no default connection (--tenarium-url)")

// Connections builds Tenarium API clients for resources. Clients are cached
// by URL and API key, so a rotated key yields a new client.
type Connections struct {
	// Reader reads TenariumConnections and Secrets. Use an uncached reader
	// (mgr.GetAPIReader()) so the operator does not need to list and watch
	// every Secret in the cluster.
	Reader  ctrlclient.Reader
	Default DefaultConnection
	// HTTPClient is used for API calls; nil means a client with a 30s timeout.
	HTTPClient *http.Client
	// Retries is the number of retries for failed safe requests.
	Retries int

	mu    sync.Mutex
	cache map[string]*client.Client
}

// For returns the client for a resource in namespace that refers to ref.
func (c *Connections) For(ctx context.Context, namespace string, ref *tenariumv1.ConnectionReference) (*client.Client, error) {
	if ref == nil {
		return c.defaultClient(ctx)
	}
	var conn tenariumv1.TenariumConnection
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &conn); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("TenariumConnection %s/%s not found", namespace, ref.Name)
		}
		return nil, err
	}
	return c.ForConnection(ctx, &conn)
}

// ForConnection returns the client described by a TenariumConnection.
func (c *Connections) ForConnection(ctx context.Context, conn *tenariumv1.TenariumConnection) (*client.Client, error) {
	key := conn.Spec.APIKeySecretRef.Key
	if key == "" {
		key = "api-key"
	}
	apiKey, err := c.secretValue(ctx, conn.Namespace, conn.Spec.APIKeySecretRef.Name, key)
	if err != nil {
		return nil, err
	}
	return c.client(conn.Spec.URL, apiKey)
}

func (c *Connections) defaultClient(ctx context.Context) (*client.Client, error) {
	d := c.Default
	if d.URL == "" {
		return nil, errNoConnection
	}
	apiKey := d.APIKey
	if apiKey == "" && d.SecretName != "" {
		key := d.SecretKey
		if key == "" {
			key = "api-key"
		}
		var err error
		if apiKey, err = c.secretValue(ctx, d.SecretNamespace, d.SecretName, key); err != nil {
			return nil, err
		}
	}
	return c.client(d.URL, apiKey)
}

func (c *Connections) secretValue(ctx context.Context, namespace, name, key string) (string, error) {
	var s corev1.Secret
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &s); err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("secret %s/%s not found", namespace, name)
		}
		return "", err
	}
	v, ok := s.Data[key]
	if !ok || len(v) == 0 {
		return "", fmt.Errorf("secret %s/%s has no key %q", namespace, name, key)
	}
	return strings.TrimSpace(string(v)), nil
}

func (c *Connections) client(url, apiKey string) (*client.Client, error) {
	sum := sha256.Sum256([]byte(url + "\x00" + apiKey))
	k := hex.EncodeToString(sum[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.cache[k]; ok {
		return cl, nil
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	opts := []client.Option{client.WithHTTPClient(hc), client.WithUserAgent(UserAgent)}
	if apiKey != "" {
		opts = append(opts, client.WithAPIKey(apiKey))
	}
	if c.Retries > 0 {
		opts = append(opts, client.WithRetry(c.Retries, 200*time.Millisecond))
	}
	cl, err := client.New(url, opts...)
	if err != nil {
		return nil, err
	}
	if c.cache == nil {
		c.cache = map[string]*client.Client{}
	}
	c.cache[k] = cl
	return cl, nil
}
