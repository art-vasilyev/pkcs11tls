# pkcs11tls
TLS client for authorization in [OpenStack Keystone](https://docs.openstack.org/keystone/latest/) by SSL certificate stored in PKCS11 token. 
Keystone should be configured for [tokenless authorization](https://docs.openstack.org/keystone/latest/admin/configure_tokenless_x509.html).

## Usage
```
pkcs11-tls --help

Command-line tool for Tokenless Authorization in the Keystone.
X.509 Client SSL Certificates are stored in the PKCS11 token.

Usage of ./pkcs11-tls:
  -cacert string
        path to the CA certificate (optional)
  -help
        show help
  -host string
        Keystone service hostname (example: keystone.stand.loc)
  -module string
        path to the PKCS11 module
  -pin string
        Smart card PIN
  -port int
        Keystone service port (default 443)
```
