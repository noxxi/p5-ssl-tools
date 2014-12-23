# Collection of SSL Tools

## Heartbleed

- check-ssl-heartbeat 
  - check for heartbleed OpenSSL vulnerability
  - supports various protocols requiring STARTTLS or similar

## SMTP TLS support (STARTTLS)

- mx_starttls_bulk 
  - bulk checking of domains for SMTP TLS support
  - fast parallel checking with non-blocking I/O: 40..60 domains/s which
    includes MX lookups and several TLS connections
  - checks for common problems with TLS support in MTA
  - does not try to verify certificates, because STARTTLS itself is open to MITM
    attacks by stripping STARTTLS support
- mx_starttls_bulk_summarize 
  - summarize data created by mx_starttls_bulk

## HTTPS: Certificate Verification, OCSP ...

- https_ocsp_bulk 
  - check lots of sites for certificate verification, ciphers and OCSP revocation problems
  - synchronous, i.e one site gets checked after the other
