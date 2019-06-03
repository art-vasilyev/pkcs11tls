package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ThalesIgnite/crypto11"
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

	slotNumber := 1
	certificates, err := loadCertificates(libPath, pin, slotNumber)

	cfg := &crypto11.Config{
		Path:       libPath,
		SlotNumber: &slotNumber,
		Pin:        pin,
	}
	context, err := crypto11.Configure(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer context.Close()

	for label, x509cert := range certificates {
		log.Printf("processing certificate label=%s\n", label)
		keyPair, err := context.FindKeyPair(nil, []byte(label))
		if err != nil {
			log.Printf("failed to get certificate keys: %s\n", err)
			continue
		}
		if keyPair == nil {
			log.Println("failed to get certificate keys")
			continue
		}

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
