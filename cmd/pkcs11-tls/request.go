package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
)

func requestToken(x509cert *x509.Certificate, keyPair crypto.Signer, cacert string, hostname string, port int) (string, error) {
	domainName := x509cert.Subject.OrganizationalUnit[0]
	identityProvider := getIdentityProvider(x509cert)
	url := fmt.Sprintf(
		"https://%s:%d/v3/OS-FEDERATION/identity_providers/%s/protocols/x509/auth",
		hostname, port, identityProvider)
	client, err := buldTLSCLient(x509cert, keyPair, cacert)
	if err != nil {
		return "", err
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-Domain-Name", domainName)
	fmt.Printf("requesting token for domain scope '%s': %s\n", domainName, url)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %s", err)
	}
	defer resp.Body.Close()
	token := resp.Header.Get("X-Subject-Token")
	return token, nil
}

func getIdentityProvider(cert *x509.Certificate) string {
	issuer := cert.Issuer
	issuerDN := fmt.Sprintf(
		"CN=%s,OU=%s,O=%s,ST=%s,C=%s",
		issuer.CommonName, issuer.OrganizationalUnit[0], issuer.Organization[0],
		issuer.Province[0], issuer.Country[0])
	s := sha256.New()
	s.Write([]byte(issuerDN))
	identityProvider := fmt.Sprintf("%x", s.Sum(nil))
	return identityProvider
}

func buldTLSCLient(x509cert *x509.Certificate, keyPair crypto.Signer, cacert string) (*http.Client, error) {
	certificate := tls.Certificate{
		Certificate: [][]byte{x509cert.Raw},
		Leaf:        x509cert,
		PrivateKey:  keyPair,
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: true,
	}
	if cacert != "" {
		caCertData, err := ioutil.ReadFile(cacert)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertData)
		tlsConfig.RootCAs = caCertPool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}
	return client, nil
}
