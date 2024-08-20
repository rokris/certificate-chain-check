# SSL Certificate Validator [![Super-Linter](https://github.com/rokris/certificate-chain-check/actions/workflows/superlint.yml/badge.svg)](https://github.com/marketplace/actions/super-linter)

This Python script validates SSL/TLS certificates for a list of server addresses. It checks the certificate chain, enforces a minimum TLS version, and validates the hostname against the certificate.

## Features

- **Certificate Chain Validation**: Ensures that the SSL/TLS certificate chain is valid for each provided server address.
- **Hostname Validation**: Verifies that the certificate's Subject Alternative Name (SAN) matches the server's hostname.
- **TLS Version Enforcement**: Enforces a minimum of TLS 1.2, disabling older, less secure versions like SSLv2 and SSLv3.
- **Error Handling**: Provides detailed error messages for issues such as invalid certificates, hostname mismatches, and connection problems.

## Prerequisites

- **Python 3.x**
- All required Python packages are listed in the `requirements.txt` file.

You can install the required packages using pip:

```bash
pip install -r requirements.txt
```

## Usage

You can run the script by providing server addresses as command-line arguments or by inputting them interactively.

### Command-Line Usage

```bash
./certificate-chain-check.py example.com example.org:8443 https://secure-site.com
```

You can specify the server address in the following formats:

```bash
- example.com
- example.com:443 (with port)
- https://example.com (the port will default to 443)
```

### Interactive Usage

If you run the script without any arguments, it will prompt you to enter the server addresses:

```bash
./certificate-chain-check.py
```

You can then enter multiple addresses separated by spaces, e.g.

```bash
./certificate-chain-check.py example.com example.org:8443 https://secure-site.com
```

### Example Output

```bash
Certificate and chain are valid for example.com
Certificate or chain validation failed for example.org: The local issuer certificate is not available
Hostname validation failed for secure-site.com
```

## Functions

- validate_certificate_chain(context, server_address, server_port): Validates the certificate chain for a given server.
- validate_hostname(cert, server_address): Validates the hostname of the certificate.
- check_certificate_chain(server_addresses, server_port): Checks the certificate chain for each server address and port combination.
- parse_address(address): Parses server addresses to extract the hostname and port.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
