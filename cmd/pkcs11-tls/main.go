package main

import (
	"C"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"unsafe"

	"github.com/miekg/pkcs11"
)

var errMalformedRSAPublicKey = errors.New("malformed RSA public key")
var errUnsupportedRSAOptions = errors.New("unsupported RSA option value")

type pkcs11Object struct {
	// The PKCS#11 object handle.
	handle pkcs11.ObjectHandle

	// The PKCS#11 context. This is used  to find a session handle that can
	// access this object.
	context *pkcs11.Ctx
	session *pkcs11.SessionHandle
}

func (o *pkcs11Object) Delete() error {
	err := o.context.DestroyObject(*o.session, o.handle)
	return err
}

// pkcs11PrivateKey contains a reference to a loaded PKCS#11 private key object.
type pkcs11PrivateKey struct {
	pkcs11Object

	// pubKeyHandle is a handle to the public key.
	pubKeyHandle pkcs11.ObjectHandle

	// pubKey is an exported copy of the public key. We pre-export the key material because crypto.Signer.Public
	// doesn't allow us to return errors.
	pubKey crypto.PublicKey
}

// Delete implements Signer.Delete.
func (k *pkcs11PrivateKey) Delete() error {
	err := k.pkcs11Object.Delete()
	if err != nil {
		return err
	}
	err = k.context.DestroyObject(*k.session, k.pubKeyHandle)
	return err
}

// Public returns the public half of a private key.
//
// This partially implements the go.crypto.Signer and go.crypto.Decrypter interfaces for
// pkcs11PrivateKey. (The remains of the implementation is in the
// key-specific types.)
func (k pkcs11PrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

// Signer is a PKCS#11 key that implements crypto.Signer.
type Signer interface {
	crypto.Signer

	// Delete deletes the key pair from the token.
	Delete() error
}

// SignerDecrypter is a PKCS#11 key implements crypto.Signer and crypto.Decrypter.
type SignerDecrypter interface {
	Signer

	// Decrypt implements crypto.Decrypter.
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
}

type pkcs11PrivateKeyRSA struct {
	pkcs11PrivateKey
}

// Sign signs a message using a RSA key.
//
// This completes the implemention of crypto.Signer for pkcs11PrivateKeyRSA.
//
// PKCS#11 expects to pick its own random data where necessary for signatures, so the rand argument is ignored.
//
// Note that (at present) the crypto.rsa.PSSSaltLengthAuto option is
// not supported. The caller must either use
// crypto.rsa.PSSSaltLengthEqualsHash (recommended) or pass an
// explicit salt length. Moreover the underlying PKCS#11
// implementation may impose further restrictions.
func (priv *pkcs11PrivateKeyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch opts.(type) {
	case *rsa.PSSOptions:
		signature, err = signPSS(priv.context, *priv.session, priv, digest, opts.(*rsa.PSSOptions))
	default: /* PKCS1-v1_5 */
		signature, err = signPKCS1v15(priv.context, *priv.session, priv, digest, opts.HashFunc())
	}

	if err != nil {
		return nil, err
	}

	return signature, err
}

func signPSS(context *pkcs11.Ctx, session pkcs11.SessionHandle, key *pkcs11PrivateKeyRSA, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	var hMech, mgf, hLen, sLen uint
	var err error
	if hMech, mgf, hLen, err = hashToPKCS11(opts.Hash); err != nil {
		return nil, err
	}
	switch opts.SaltLength {
	case rsa.PSSSaltLengthAuto: // parseltongue constant
		// TODO we could (in principle) work out the biggest
		// possible size from the key, but until someone has
		// the effort to do that...
		return nil, errUnsupportedRSAOptions
	case rsa.PSSSaltLengthEqualsHash:
		sLen = hLen
	default:
		sLen = uint(opts.SaltLength)
	}
	// TODO this is pretty horrible, maybe the PKCS#11 wrapper
	// could be improved to help us out here
	parameters := concat(ulongToBytes(hMech),
		ulongToBytes(mgf),
		ulongToBytes(sLen))
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, parameters)}
	if err = context.SignInit(session, mech, key.handle); err != nil {
		return nil, err
	}
	return context.Sign(session, digest)
}

func ulongToBytes(n uint) []byte {
	return C.GoBytes(unsafe.Pointer(&n), C.sizeof_ulong) // ugh!
}

func bytesToUlong(bs []byte) (n uint) {
	return *(*uint)(unsafe.Pointer(&bs[0])) // ugh
}

func concat(slices ...[]byte) []byte {
	n := 0
	for _, slice := range slices {
		n += len(slice)
	}
	r := make([]byte, n)
	n = 0
	for _, slice := range slices {
		n += copy(r[n:], slice)
	}
	return r
}

func hashToPKCS11(hashFunction crypto.Hash) (uint, uint, uint, error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
	default:
		return 0, 0, 0, errUnsupportedRSAOptions
	}
}

var pkcs1Prefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func signPKCS1v15(context *pkcs11.Ctx, session pkcs11.SessionHandle, key *pkcs11PrivateKeyRSA, digest []byte, hash crypto.Hash) (signature []byte, err error) {
	/* Calculate T for EMSA-PKCS1-v1_5. */
	oid := pkcs1Prefix[hash]
	T := make([]byte, len(oid)+len(digest))
	copy(T[0:len(oid)], oid)
	copy(T[len(oid):], digest)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
	err = context.SignInit(session, mech, key.handle)
	if err == nil {
		signature, err = context.Sign(session, T)
	}
	return
}

func main() {
	libPathPtr := flag.String("module", "", "path to the PKCS11 module")
	pinPtr := flag.String("pin", "", "Smart card PIN")
	identityURL := flag.String("identity-url", "", "URL of the Identity (Keystone) service (example: https://keystone.stand.loc:443)")
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

	p := pkcs11.New(*libPathPtr)
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, *pinPtr)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	certHandles, err := findCertificates(p, session)
	if err != nil {
		panic(err)
	}

	for _, certHandle := range certHandles {
		certLabel, err := getLabel(certHandle, p, session)
		if err != nil {
			panic(err)
		}
		certData, err := getValue(certHandle, p, session)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\nProcessing certificate label=%s\n", string(certLabel))

		privHandle, err := getPrivateKey(certLabel, p, session)
		if err != nil {
			fmt.Printf("failed to get certificate private key: %s\n", err)
			continue
		}

		pubHandle, err := getPublicKey(certLabel, p, session)
		if err != nil {
			fmt.Printf("failed to get certificate public key: %s\n", err)
			continue
		}

		pubKey, err := exportRSAPublicKey(*pubHandle, p, session)
		if err != nil {
			fmt.Printf("failed to parse RSA key: %s\n", err)
			continue
		}
		k := &pkcs11PrivateKeyRSA{
			pkcs11PrivateKey: pkcs11PrivateKey{
				pkcs11Object: pkcs11Object{
					handle:  *privHandle,
					context: p,
					session: &session,
				},
				pubKeyHandle: *pubHandle,
				pubKey:       pubKey,
			},
		}

		x509cert, _ := x509.ParseCertificate(certData)
		fmt.Printf("Certificate subject: %s\n", x509cert.Subject)
		domainName := x509cert.Subject.OrganizationalUnit[0]
		certificate := tls.Certificate{
			Certificate: [][]byte{x509cert.Raw},
			Leaf:        x509cert,
			PrivateKey:  k,
		}

		// Load CA cert
		// caCert, err := ioutil.ReadFile(cacert)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// caCertPool := x509.NewCertPool()
		// caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: true,
			// RootCAs:      caCertPool,
		}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client := &http.Client{Transport: transport}

		url := fmt.Sprintf("%s/v3/OS-FEDERATION/identity_providers/9519a95c0cb0594454e5705d1a77a541802fa14d679ed7c12aea633b6876266c/protocols/x509/auth", *identityURL)
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

func findCertificates(context *pkcs11.Ctx, session pkcs11.SessionHandle) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)}
	err := context.FindObjectsInit(session, template)
	if err != nil {
		return nil, err
	}

	certHandles, _, err := context.FindObjects(session, 10)
	err = context.FindObjectsFinal(session)
	if err != nil {
		return nil, err
	}
	return certHandles, nil
}

func getPrivateKey(label []byte, context *pkcs11.Ctx, session pkcs11.SessionHandle) (*pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	err := context.FindObjectsInit(session, template)
	if err != nil {
		return nil, err
	}
	privHandles, _, err := context.FindObjects(session, 1)
	err = context.FindObjectsFinal(session)
	if err != nil {
		return nil, err
	}
	if len(privHandles) == 0 {
		return nil, fmt.Errorf("unable to find private key with label %s", string(label))
	}
	return &privHandles[0], nil
}

func getPublicKey(label []byte, context *pkcs11.Ctx, session pkcs11.SessionHandle) (*pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	err := context.FindObjectsInit(session, template)
	if err != nil {
		return nil, err
	}
	pubHandles, _, err := context.FindObjects(session, 1)
	err = context.FindObjectsFinal(session)
	if err != nil {
		return nil, err
	}
	if len(pubHandles) == 0 {
		return nil, fmt.Errorf("unable to find public key with label %s", string(label))
	}
	return &pubHandles[0], nil
}

func getLabel(obj pkcs11.ObjectHandle, context *pkcs11.Ctx, session pkcs11.SessionHandle) ([]byte, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil)}
	attrs, err := context.GetAttributeValue(session, obj, template)
	if err != nil {
		return nil, err
	}
	return attrs[0].Value, nil
}

func getValue(obj pkcs11.ObjectHandle, context *pkcs11.Ctx, session pkcs11.SessionHandle) ([]byte, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}
	attrs, err := context.GetAttributeValue(session, obj, template)
	if err != nil {
		return nil, err
	}
	return attrs[0].Value, nil
}

func exportRSAPublicKey(pubHandle pkcs11.ObjectHandle, context *pkcs11.Ctx, session pkcs11.SessionHandle) (crypto.PublicKey, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}
	exported, err := context.GetAttributeValue(session, pubHandle, template)
	if err != nil {
		return nil, err
	}
	var modulus = new(big.Int)
	modulus.SetBytes(exported[0].Value)
	var bigExponent = new(big.Int)
	bigExponent.SetBytes(exported[1].Value)
	if bigExponent.BitLen() > 32 {
		return nil, errMalformedRSAPublicKey
	}
	if bigExponent.Sign() < 1 {
		return nil, errMalformedRSAPublicKey
	}
	exponent := int(bigExponent.Uint64())
	result := rsa.PublicKey{
		N: modulus,
		E: exponent,
	}
	if result.E < 2 {
		return nil, errMalformedRSAPublicKey
	}
	return &result, nil
}
