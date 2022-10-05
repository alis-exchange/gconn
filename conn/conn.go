package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/status"
	"strings"
)

type grpcTokenSource struct {
	oauth.TokenSource
}

// NewConn creates a new gRPC connection.
// host should be of the form domain:port, e.g., example.com:443
func NewConn(ctx context.Context, host string, insecure bool) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	if host != "" {
		opts = append(opts, grpc.WithAuthority(host))
	}

	if insecure {
		opts = append(opts, grpc.WithInsecure())
	} else {
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		cred := credentials.NewTLS(&tls.Config{
			RootCAs: systemRoots,
		})
		opts = append(opts, grpc.WithTransportCredentials(cred))
	}

	// use a tokenSource to automatically inject tokens with each underlying client request
	audience := "https://" + strings.Split(host, ":")[0]
	tokenSource, err := idtoken.NewTokenSource(ctx, audience, option.WithAudiences(audience))
	if err != nil {
		return nil, status.Errorf(
			codes.Unauthenticated,
			"NewTokenSource: %s", err,
		)
	}
	opts = append(opts, grpc.WithPerRPCCredentials(grpcTokenSource{
		TokenSource: oauth.TokenSource{
			tokenSource,
		},
	}))

	return grpc.Dial(host, opts...)
}
