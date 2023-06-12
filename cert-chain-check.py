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

# ANSI color codes for colorizing the output
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"


def print_colored(text, color):
    """
    Prints the given text in the specified color.
    """
    print(color + text + COLOR_RESET)


def validate_certificate_chain(context, server_address, server_port):
    """
    Validates the certificate chain for the given server address and port.
    Returns the loaded certificate object if successful.
    Raises SSL errors if certificate validation fails.
    """
    with context.wrap_socket(socket.socket(), server_hostname=server_address) as s:
        s.connect((server_address, server_port))
        cert_der = ssl.DER_cert_to_PEM_cert(s.getpeercert(binary_form=True))

        # Validate the certificate chain
        cert_store = context.get_ca_certs()
        cert = load_pem_x509_certificate(cert_der.encode(), default_backend())
        cert_store.append(cert)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False  # Disable default hostname validation
        context.cert_store = cert_store

    return cert


def validate_hostname(cert, server_address):
    """
    Validates the hostname of the certificate against the server address.
    Raises SSL errors if hostname validation fails.
    """
    try:
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        cert_alt_names = san_extension.value.get_values_for_type(DNSName)
        for alt_name in cert_alt_names:
            if fnmatch.fnmatch(server_address, alt_name):
                return True
        raise ssl.CertificateError(f"Hostname mismatch: expected {server_address}, got {cert_alt_names}")
    except ExtensionNotFound:
        raise ssl.CertificateError("Certificate does not contain Subject Alternative Name (SAN) extension")


def check_certificate_chain(server_addresses, server_port):
    """
    Checks the certificate chain for each server address and port combination.
    Prints the validation results for each server.
    """
    try:
        # Create an SSL context and connect to each server
        context = ssl.create_default_context(cafile=certifi.where())

        for server_address in server_addresses:
            try:
                cert = validate_certificate_chain(context, server_address, server_port)
                validate_hostname(cert, server_address)

                print_colored(f"Certificate and chain are valid for {server_address}", COLOR_GREEN)

            except ssl.SSLError as e:
                error_message = str(e)
                if "unable to get local issuer certificate" in error_message:
                    print_colored(f"Certificate or chain validation failed for {server_address}: The local issuer certificate is not available", COLOR_RED)
                else:
                    print_colored(f"Certificate or chain validation failed for {server_address}: {error_message}", COLOR_RED)

            except ssl.CertificateError as e:
                error_message = str(e)
                print_colored(f"Hostname validation failed for {server_address}", COLOR_RED)

            except ConnectionResetError:
                print_colored(f"Connection reset by peer for {server_address}", COLOR_RED)

            except ConnectionRefusedError:
                print_colored(f"Connection refused by peer for {server_address}", COLOR_RED)

    except socket.gaierror:
        print_colored("Invalid server address or hostname not known", COLOR_RED)


if __name__ == '__main__':
    # Get the server addresses from command-line arguments
    server_addresses = sys.argv[1:]
    server_port = 443
    # Check if no command-line arguments are provided
    if not server_addresses:
        # Prompt for server addresses if none are provided
        server_addresses = input("Enter the server addresses (separated multiple hosts with spaces): ").split()
        server_port = input("Enter the server port (default port is 443): ")
        if server_port: 
            server_port = int(server_port)
        else:
            server_port = 443
    check_certificate_chain(server_addresses, server_port)
