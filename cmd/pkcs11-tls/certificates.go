package main

import (
	"crypto/x509"
	"fmt"

	"github.com/miekg/pkcs11"
)

func loadCertificates(libPath string, pin string, slotNumber int) (map[string]*x509.Certificate, error) {
	certificates := make(map[string]*x509.Certificate)

	p := pkcs11.New(libPath)
	err := p.Initialize()
	if err != nil {
		return nil, err
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	if len(slots) < slotNumber {
		return nil, fmt.Errorf("unable to find slot %d", slotNumber)
	}
	session, err := p.OpenSession(uint(slotNumber)-1, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		return nil, err
	}
	defer p.Logout(session)

	certHandles, err := findCertificates(p, session, nil, nil, 10)
	for _, certHandle := range certHandles {
		label, err := getAttribute(p, session, certHandle, pkcs11.CKA_LABEL)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate label: %s", err)
		}
		certValue, err := getAttribute(p, session, certHandle, pkcs11.CKA_VALUE)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate data: %s", err)
		}
		x509cert, err := x509.ParseCertificate(certValue)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate data: %s", err)
		}
		certificates[string(label)] = x509cert
	}
	return certificates, nil
}

// findCertificates retrieves certificates, or nil if they cannot be found.
//
// Both id and label may be nil to get list of all certificates.
func findCertificates(context *pkcs11.Ctx, session pkcs11.SessionHandle, id []byte, label []byte, max int) ([]pkcs11.ObjectHandle, error) {
	var certHandles []pkcs11.ObjectHandle

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)}
	if id != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))
	}
	if err := context.FindObjectsInit(session, template); err != nil {
		return nil, err
	}
	defer context.FindObjectsFinal(session)
	handles, _, err := context.FindObjects(session, max)
	certHandles = handles
	if err != nil {
		return nil, err
	}
	return certHandles, nil
}

func getAttribute(context *pkcs11.Ctx, session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, attribute uint) ([]byte, error) {
	attributes := []*pkcs11.Attribute{pkcs11.NewAttribute(attribute, nil)}
	attrs, err := context.GetAttributeValue(session, handle, attributes)
	if err != nil {
		return nil, err
	}
	return attrs[0].Value, nil
}
