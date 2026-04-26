## DNS

- `src/protocols/dns.cpp`: release build warns that `pseudo_header` may be used uninitialized. Investigate before trusting DNS forged-response checksum behavior.

## NAT

- `src/protocols/nat.cpp`: NAT Exhaustion previously hid `sendto()` failures and built an incomplete `sockaddr_ll`, which made manual runs appear active while no packets were visible. Bounded execution, startup diagnostics, send-error counters, backpressure handling, and a stop summary have been added. EAGAIN/EWOULDBLOCK/ENOBUFS are treated as expected kernel backpressure and summarized at shutdown.
