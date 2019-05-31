package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/miekg/pkcs11"

	"github.com/art-vasilyev/crypto11"
)

func main() {
	libPathPtr := flag.String("module", "", "path to the PKCS11 module")
	pinPtr := flag.String("pin", "", "Smart card PIN")
	identityURL := flag.String("identity-url", "", "URL of the Identity (Keystone) service (example: https://keystone.stand.loc:443)")
	caCertPtr := flag.String("cacert", "", "path to the CA certificate (optional)")
	flag.Parse()
	if *libPathPtr == "" {
		log.Fatal("-module is required")
	}
	if *pinPtr == "" {
		log.Fatal("-pin is required")
	}
	if *identityURL == "" {
		log.Fatal("-identity-url is required")
	}
	slotNumber := 1
	cfg := &crypto11.Config{
		Path:       *libPathPtr,
		SlotNumber: &slotNumber,
		Pin:        *pinPtr,
	}
	context, err := crypto11.Configure(cfg)
	if err != nil {
		log.Fatal(err)
	}
	certHandles, err := context.FindCertificates(nil, nil, 10)
	if err != nil {
		log.Fatalf("Failed to get certificates: %s\n", err)
	}
	for _, certHandle := range certHandles {
		label, err := context.GetAttribute(certHandle, pkcs11.CKA_LABEL)
		if err != nil {
			log.Printf("failed to get certificate label: %s\n", err)
			continue
		}
		log.Printf("processing certificate label=%s\n", label)
		certValue, err := context.GetAttribute(certHandle, pkcs11.CKA_VALUE)
		if err != nil {
			log.Printf("failed to get certificate data: %s\n", err)
			continue
		}
		keyPair, err := context.FindKeyPair(nil, label)
		if err != nil {
			log.Printf("failed to get certificate keys: %s\n", err)
			continue
		}
		if keyPair == nil {
			log.Println("failed to get certificate keys")
			continue
		}
		x509cert, _ := x509.ParseCertificate(certValue)
		fmt.Printf("Certificate subject: %s\n", x509cert.Subject)
		domainName := x509cert.Subject.OrganizationalUnit[0]
		certificate := tls.Certificate{
			Certificate: [][]byte{x509cert.Raw},
			Leaf:        x509cert,
			PrivateKey:  keyPair,
		}

		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: true,
		}
		if *caCertPtr != "" {
			caCert, err := ioutil.ReadFile(*caCertPtr)
			if err != nil {
				log.Fatal(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client := &http.Client{Transport: transport}

		identityProvider := getIdentityProvider(x509cert)
		url := fmt.Sprintf("%s/v3/OS-FEDERATION/identity_providers/%s/protocols/x509/auth", *identityURL, identityProvider)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Add("X-Domain-Name", domainName)
		fmt.Printf("requesting token for domain scope '%s': %s\n", domainName, url)
		resp, err := client.Do(req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("request failed: %s", err)
			continue
		}
		fmt.Printf("Response: %s\n", string(data))
		token := resp.Header.Get("X-Subject-Token")
		if token != "" {
			fmt.Printf("Token: %s\n", token)
			break
		}
	}
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
