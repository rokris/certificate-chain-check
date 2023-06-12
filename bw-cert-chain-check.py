#!/usr/bin/env python3

import sys
import ssl
import socket
import certifi
import fnmatch
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import ExtensionNotFound, DNSName

def check_certificate_chain(server_addresses):
    try:
        # Create an SSL context and connect to each server
        context = ssl.create_default_context(cafile=certifi.where())

        for server_address in server_addresses:
            try:
                with context.wrap_socket(socket.socket(), server_hostname=server_address) as s:
                    s.connect((server_address, 443))
                    cert_der = ssl.DER_cert_to_PEM_cert(s.getpeercert(binary_form=True))

                    # Validate the certificate chain
                    cert_store = context.get_ca_certs()
                    cert = load_pem_x509_certificate(cert_der.encode(), default_backend())
                    cert_store.append(cert)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.check_hostname = False  # Disable default hostname validation
                    context.cert_store = cert_store

                # Validate the hostname against Subject Alternative Names (SAN)
                try:
                    san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    cert_alt_names = san_extension.value.get_values_for_type(DNSName)
                    for alt_name in cert_alt_names:
                        if fnmatch.fnmatch(server_address, alt_name):
                            break
                    else:
                        raise ssl.CertificateError(f"Hostname mismatch: expected {server_address}, got {cert_alt_names}")
                except ExtensionNotFound:
                    raise ssl.CertificateError("Certificate does not contain Subject Alternative Name (SAN) extension")

                print(f"Certificate and chain are valid for {server_address}.")

            except ssl.SSLError as e:
                error_message = str(e)
                if "unable to get local issuer certificate" in error_message:
                    print(f"Certificate or chain validation failed for {server_address}: The local issuer certificate is not available.")
                else:
                    print(f"Certificate or chain validation failed for {server_address}: {error_message}")

            except ssl.CertificateError as e:
                error_message = str(e)
                print(f"Hostname validation failed for {server_address}: {error_message}")

    except socket.gaierror:
        print("Invalid server address or hostname not known.")

if __name__ == '__main__':
    # Get the server addresses from command-line arguments
    server_addresses = sys.argv[1:]
    # Check if no command-line arguments are provided
    if not server_addresses:
        # Prompt for server addresses if none are provided
        server_addresses = input("Enter the server addresses (separated by spaces): ").split()
    check_certificate_chain(server_addresses)
