package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/miekg/pkcs11"

	"github.com/art-vasilyev/crypto11"
)

func main() {
	var (
		libPath  string
		pin      string
		hostname string
		port     int
		cacert   string
		help     bool
	)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.StringVar(&libPath, "module", "", "path to the PKCS11 module")
	flag.StringVar(&pin, "pin", "", "Smart card PIN")
	flag.StringVar(&hostname, "host", "", "Keystone service hostname (example: keystone.stand.loc)")
	flag.IntVar(&port, "port", 443, "Keystone service port")
	flag.StringVar(&cacert, "cacert", "", "path to the CA certificate (optional)")
	flag.BoolVar(&help, "help", false, "show help")
	var description = `
Command-line tool for Tokenless Authorization in the Keystone.
X.509 Client SSL Certificates are stored in the PKCS11 token.
`
	flag.Parse()
	if help == true {
		fmt.Println(description)
		flag.Usage()
		os.Exit(0)
	}
	if libPath == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if pin == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if hostname == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	context, err := crypto11Configure(libPath, pin)
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

		token, err := requestToken(x509cert, keyPair, cacert, hostname, port)
		if err != nil {
			log.Println(err)
			continue
		}
		if token != "" {
			fmt.Printf("token=%s\n", token)
			break
		}
	}
}

func crypto11Configure(libPath string, pin string) (*crypto11.Context, error) {
	slotNumber := 1
	cfg := &crypto11.Config{
		Path:       libPath,
		SlotNumber: &slotNumber,
		Pin:        pin,
	}
	context, err := crypto11.Configure(cfg)
	if err != nil {
		return nil, err
	}
	return context, nil
}

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
