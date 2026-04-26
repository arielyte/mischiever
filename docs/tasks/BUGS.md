## DNS

- `src/protocols/dns.cpp`: release build warns that `pseudo_header` may be used uninitialized. Investigate before trusting DNS forged-response checksum behavior.