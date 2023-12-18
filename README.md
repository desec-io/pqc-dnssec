# DNSSEQ: PowerDNS with Post-quantum signatures

PowerDNS-and-Bind9-based proof-of-concept implementation of DNSSEC using the post-quantum signature schemes FALCON512<sup>\*+</sup>,
Dilithium2<sup>\*</sup>, and SPHINCS+-SHA256-128s<sup>\*</sup>.

\* denotes Bind9 support.

+ denotes PowerDNS support.

## Usage

This repository can be used to provide either a local test setup, serve as a test setup on the Internet, or both.
It contains both a FALCON-enabled authoritative DNS server and DNS recursor.

### Local Test Setup

To test the PoC locally, clone this repository, install docker and docker-compose, and run `setup.py`. `setup.py`
has two optional arguments: `--bind9` and `--pdns` which specifies which implementation you wish to initialize.
By default, if no arguments are specified, PowerDNS gets initialized.


To test all implementations, run the following commands:
```
docker-compose up -d
python3 setup.py --bind9 --pdns
```

To run `setup.py`, Python 3.9, and some packages are required. If you want a clean install, create a virtual
environment and then run the setup:

```
python3 -m venv venv
source venv/bin/activate
python3 -m pip install dnspython requests  # TODO include requirements.txt
python3 setup.py
```

The setup script will configure the authoritative with the following zones under `.example.`:

- signed with 2048-bit RSA: `rsasha1.example.`, `rsasha256.example.`, `rsasha512.example.`
- signed with elliptic curve algorithms: `ecdsa256.example.`, `ecdsa384.example.`
- signed with Edwards curve algorithhms: `ed25519.example.`, `ed448.example.`
- signed with post-quantum algorithm FALCON: `falcon.example.`, `dilithium.example.`, `sphincs.example.`

Note: Currently only the bind9 based authoritative and recursor support `dilithium.example.` and `sphincs.example.`. Adding
these algorithms to PowerDNS is an ongoing project.

Both zones contain A and AAAA records pointing to localhost, as well as a TXT record stating the purpose of the zones.
The zones are also equipped with A, AAAA, and TXT wildcard records.
You can query the authoritative DNS server directly at `localhost:5301` (tcp/udp).

The recursors, available at `localhost:5302` (PowerDNS), and `localhost:5304` (Bind9) for both UDP and TCP, are now configured
with the appropriate trust anchor for `.example`, so that queries for above zones will validated and answered with
authenticated data (AD) bit:

```
$ dig TXT @localhost -p 5302 falcon.example. +dnssec
[...]

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 55224
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

[...]

;; ANSWER SECTION:
falcon.example.		3590	IN	TXT	"FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon"
falcon.example.		3590	IN	RRSIG	TXT 17 2 3600 20220113000000 20211223000000 948 falcon.example. OejPqJXFparczRg6+gLVPn1IVgayZOk8N+t/H92ViSuR7JMEkHmHK7lM Z2tXQbWT7jL25pSDiDvWRj4/X8kvbUxGAJUaFN/rM99N2VWnDGzoxylk R54flObVvNjghxm+j3lb3ox4u3x3rOqEb5m9WrkfpeVbldK6susSn7fp q2if9MUNgvfOfrjQCCz1E2cifBw9Dev2SUQJ5NDRvfT4bcZIvnL47FZm F4xH6BcXhv7SqDQd9E6oYtrJ6Q1IzHR7VRq0VW6R2Bo3BDaKL9KV03yR LXNUxr6Z442uVa/bOk4lKvcnymTLZ0LfwRxcElsFWiw2/5Q3r4vACtJI Vz922ZJQ4JhXpRs80UrapYOD6ame78GtRbfoEe6qrNQnUpeoybvIx4vZ zN+tE6lUewTDpolFJUSxJlpkmbAvUATxWXJwDrftFpZhTimjYL1b2hYt WDXbjOM7EciluBzUMj3M0qFx/dTd/ETqccf56Cl93WKPPiDGSYebR2I3 Vy5pPpVGWEx23gApbMHg9Joiz5QxdKhFp1BZsp93eODTIiizdfXDrl+m gp8lORM1Z5SIkzPR22rIB6GuNl4f/Xk9Tsms8a2nerTMimKzNFb5e3sP jo1pGKZuSQsAj5hmNIkqXHgvX+M8u087tIy2gsNT2sJ3qR79PGRLoreD mS6YhXIMWuA/uOXm/l1mJk0uSw4AiyRFpT/d8kQVP47mkBUraSMzvAzb kvWzXMS6e9/2ZUhSo1tV+Zx+Nx9/4lkgYoHe0rebqUazj2jOVnM4NCSb qa8tR5zA6yk61p02QZJS2LCdchfywxlUQcaK0VNW/n768GyeJkFU59Zy e9cqpmIxrzKQsSmMqbxVYJQLkGLtsrQR36/A

[...]
```

Congratulations, you have just used FALCON to authenticate a DNSSEC query!

### Internet Test Setup

To use the Internet Test Setup, a public IP address for the authoritative name server is required, and a name needs to
be delegated to this server.
Also, docker must run **without** the userland proxy.
Given a deSEC.io domain name and access token, this repository can take care of delegation itself.
To activate the Internet Test Setup, add the following variables to the `.env` file:
(A template can be found in `.env.dist`.)

```
PUBLIC_IP4_ADDRESSES=10.1.1.1,10.2.2.2
PUBLIC_IP6_ADDRESSES=fe80::1337,fe80::4711
DESEC_TOKEN=123456789abcedfghij
DESEC_DOMAIN=mytest.dedyn.io
```

At least one value for `PUBLIC_IP4_ADDRESSES` or `PUBLIC_IP6_ADDRESSES` is required. Note that if only supplied an IP4
or IP6 address, the server will not be reachable from the other IP space, which may break testing for some clients.
If you do not have a deSEC account, a `DESEC_TOKEN` can be obtained free of charge from desec.io.
Otherwise, use your existing account.

For connectivity with the global DNS, it will be required that the authoritative server can be reached on port 53.
This can be achieved by setting this value in your `.env` file:

```
PUBLIC_TCP_UDP_PORT_AUTH=53
```

This can only work if there is no other service running on port 53.
However, some operating systems run a stub resolver on port 53.
On Ubuntu, the local stub resolver can be replaced with using Google's and/or Cloudflare's resolver service by using

```
systemctl disable systemd-resolved
systemctl stop systemd-resolved
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

After setting up the `.env` file, run the setup script again: `python3 setup.py`.  # TODO make sure it doesn't duplicate
The setup will create additional zones on your authoritative server,

- signed with 2048-bit RSA: `rsasha1.example.${DESEC_DOMAIN}.`, `rsasha256.example.${DESEC_DOMAIN}.`,
    `rsasha512.example.${DESEC_DOMAIN}.`
- signed with elliptic curve algorithms: `ecdsa256.example.${DESEC_DOMAIN}.`, `ecdsa384.example.${DESEC_DOMAIN}.`
- signed with Edwards curve algorithhms: `ed25519.example.${DESEC_DOMAIN}.`, `ed448.example.${DESEC_DOMAIN}.`
- signed with post-quantum algorithm FALCON: `falcon.example.${DESEC_DOMAIN}.`, `dilithium.example.${DESEC_DOMAIN}.`,
`sphincs.example.${DESEC_DOMAIN}.`

and use the `DESEC_TOKEN` to delegate `example.$DESEC_DOMAIN` to your local authoritative name server. (Before running,
make your `DESEC_DOMAIN` exists in your deSEC account.)

To query your authoritative name server, use

```
dig TXT @localhost -p 5302 falcon.example.$DESEC_DOMAIN +dnssec
[...]
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63848
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

[...]

;; ANSWER SECTION:
falcon.example.pq-dnssec.dedyn.io.	3600 IN	TXT	"FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon"
falcon.example.pq-dnssec.dedyn.io.	3600 IN	RRSIG	TXT 17 5 3600 20220113000000 20211223000000 14823 falcon.example.pq-dnssec.dedyn.io. OU91GAL4bTBl7n0OvLLbvTysZ0vnr9hKVas6+BbWp+XI54Ju/Vht3GI6 tyjpAIpMC2xPLtZAdGzJUkgc5TISP11jO8Bw3LMmQx0EEQrY5Ff2rtUu bT7c6h4hvm1oMq7+zqTmT2S+Hi0t10FxdkVjaEHFao5dtbUswvbTKHtJ SRkXJyvGwKpE+FoSpLFiytf7UPm6wEclTRqC658eMXRclX4/o5nO3DXu tvHhWr4yYMOSEmzNsynqSKP1Nm7Rio2R+bG61MHSrQzPh7RP33yigw7n 8rJPNdv+ObZo8vUDTGIHd4vFxXdn0VLrVpolVr7GSXKQ4j9yaqV+M7xi Zb6YUZwinTmdwUbFylSNy07iXCSsRNtWkEvNFrrGicVRzLKnEdn3ni2L mRItR899U5qbbsomlkX0kp5OgduisD8VY8akNyiSfk4aCCXPCklcaOs6 /blR4qlofl6ccJ1zm+M8MQ2JksjlmrZA5GikkBmz7OyWpCU0v1o29Hrq nG94Xsp1WKYfPekZOIaWuZ5KPvhEEV5lWWHBiZx2rtFGaGBpkoT3r5tj 3Nrr+Nm9qkJBtFH+vl1h2aafrXwA43z7FJ5KLHC2HPdd+W14aeRkv2Ss /w3lfSVMoM6ten6s6f2nH873TZNN7Xb/7Axgn16/cDbJTS6an1zbgYHX Jla22Jh9m2nXutnqcJOahOZDLYZwjIilyTFHExt1liN9tAZCfDyQeUmb Mu1iYrbgzB2BiTrd9s9cSR8sGTtL/8lfdrO8MllT/4sYX+6a8euLYyHo 2rNu+M0Tv6+KYfzDzhhWXJzfRRjeqDRjR07NaJe5Uy3QYA3OUritTqnK dCt060hZVqMlhsonfrkMOpaiM9P/ik0o18xfog==

[...]
```

**Congratulations, you just extended the global DNS with a sub-tree that uses FALCON signatures!**

Now that your PoC is globally reachable, you can use any other resolver to query the name.
However, observe that other resolvers do not support FALCON signatures and thus do not set the authenticated data (AD)
bit.

## Performance

The recursor in this repository is configured to use limited caching.
In particular, aggressive NSEC caching is disabled, which means that requests matching wildcard records trigger
signature validation.
Together with the wildcards configured for the test domains,
this can be used to compare the performance of various signature validation algorithms.

The authoritative DNS server also ships tooling to measure crypto library speed:

```
docker-compose exec auth pdnsutil test-algorithms
```

## Tools

To debug queries against the powerdns recursor, set up the query trace:

```
docker-compose exec recursor rec_control trace-regex '.*example.*'
```

To list all zones the powerdns authoritative DNS server serves, use:

```
docker-compose exec auth pdnsutil list-all-zones
```

To export all zone data from the powerdns authoritative DNS server, use:

```
docker-compose exec auth bash -c 'echo ".dump" | sqlite3 /var/lib/powerdns/pdns.sqlite3'
```

To dump powerdns recursor statistics into the log file, including the percentage of cache hits, use:

```
docker-compose exec recursor pkill -SIGUSR1 pdns
```

## Acknowledgements

The PowerDNS and openssl forks used for this work was developed by [@gothremote](https://github.com/gothremote/),
who worked on this for his Master's thesis.
The Bind9 implementation used for this work was developed by [@Martyrshot](https://github.com/Martyrshot),
which was originally worked on as part of his Master's thesis and updated during his time at [SandboxAQ](https://www.sandboxaq.com).
