package adminbgservice

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"

	"github.com/hiddify/hiddify-core/v2/hcore/vpnservice"
	hutils "github.com/hiddify/hiddify-core/v2/hutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// serviceTLS makes the certificate the service presents until it stops: a new key at each start,
// never written anywhere, and the server option that serves with it. The endpoint carries the
// certificate the clients then accept, and no other.
func serviceTLS(listener net.Listener) (vpnservice.Endpoint, grpc.ServerOption, error) {
	pair, err := hutils.GenerateCertificatePair()
	if err != nil {
		return vpnservice.Endpoint{}, nil, err
	}
	certificate, err := tls.X509KeyPair(pair.Certificate, pair.PrivateKey)
	if err != nil {
		return vpnservice.Endpoint{}, nil, err
	}
	endpoint := vpnservice.Endpoint{Address: listener.Addr().String(), Certificate: string(pair.Certificate)}
	if err := endpoint.Validate(); err != nil {
		return vpnservice.Endpoint{}, nil, err
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	return endpoint, grpc.Creds(creds), nil
}

// publishEndpoint tells the app's core and the console launcher where the installed service
// listens, and which certificate it presents (vpnservice.EndpointFile): a new file, readable by
// users and written only by SYSTEM, Administrators or root.
func publishEndpoint(endpoint vpnservice.Endpoint) error {
	raw, err := endpoint.Marshal()
	if err != nil {
		return err
	}
	if err := writePublicFile(vpnservice.EndpointPath(), raw); err != nil {
		return fmt.Errorf("publish the VPN service's address: %w", err)
	}
	return nil
}

// withdrawEndpoint removes the endpoint of a service that stops: a client then finds no address
// instead of a port another program may take.
func withdrawEndpoint() {
	_ = os.Remove(vpnservice.EndpointPath())
}
