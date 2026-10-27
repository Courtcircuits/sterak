# STUN Timing tester

## Usage

```bash
./sterak stun --host stun.cloudflare.com:3478 --pcap --runs 10 --scenario both --timeout 2s
```

## Output

```
go run main.go -runs 1000
Starting STUN requests...
   0% |                                                                                | (0/1000, 0 it/hr) [0s:0s]
Your IP is: 2603:7000:dc3c:c360::3db3
 100% |████████████████████████████████████████████████████████████████████████████| (1000/1000, 51 it/s)         

First request time: 19273 μs

Results:
Successful requests: 1000
Failed requests: 0

┌───────┬───────────┐
│ %tile │ Time (μs) │
├───────┼───────────┤
│  p0   │     10505 │
│  p25  │     17096 │
│  p50  │     19661 │
│  p75  │     21014 │
│ p100  │     44582 │
└───────┴───────────┘

Latency Distribution (μs):
 10505 -  12208 |                                          | 2
 12208 -  13912 |                                          | 1
 13912 -  15616 | ████████                                 | 49
 15616 -  17320 | ████████████████████████████████████████ | 234
 17320 -  19024 | ██████████████████████████               | 153
 19024 -  20728 | ████████████████████████████████████████ | 234
 20728 -  22431 | █████████████████████████████████        | 195
 22431 -  24135 | █████████                                | 56
 24135 -  25839 | ████                                     | 26
 25839 -  27543 | ███                                      | 20
 27543 -  29247 | █                                        | 9
 29247 -  30951 |                                          | 3
 30951 -  32655 |                                          | 3
 32655 -  34358 | █                                        | 7
 34358 -  36062 |                                          | 5
 36062 -  37766 |                                          | 0
 37766 -  39470 |                                          | 2
 39470 -  41174 |                                          | 0
 41174 -  42878 |                                          | 0
 42878 -  44582 |                                          | 1
```

# TURN legit traffic

```bash
./sterak turn --host turn.example.com:3478 --username alice --password s3cret --runs 100 --concurrency 4 --scenario legit
```

Each run opens a fresh UDP socket (new 5-tuple) and performs, with per-operation latency reported:

1. `allocate-challenge`: Allocate without credentials (expects `401` + REALM/NONCE)
2. `allocate`: Allocate with long-term credentials (REQUESTED-TRANSPORT=UDP, checks XOR-RELAYED-ADDRESS)
3. `create-permission`: CreatePermission for `--peer` (default `203.0.113.5:4000`)
4. `channel-bind`: ChannelBind of channel `0x4000` to `--peer`
5. `channel-data` (only with `--channel-data`): one ChannelData message of `--data-size` bytes (default 64, random payload) sent to the peer through channel `0x4000`. The server does not acknowledge ChannelData, so the reported latency is the local send time. The peer receives real UDP traffic from the relay, so point `--peer` at a host you own (or use `--peer-listen`).
6. `send-indication` (only with `--send-indication`): one Send indication of `--data-size` bytes to the peer (no reply; latency is again local send time)
7. `peer-receive-channel-data` / `peer-receive-send-indication` (only with `--peer-listen`): see below
8. Refresh with LIFETIME=0 to free the allocation (best-effort, not measured)

`--runs` is sessions per worker; `--concurrency` workers run in parallel. A `438 Stale Nonce` is retried once with the new nonce. A server that does not require auth is also supported (no credentials needed). `username`/`password`/`peer`/`channel_data`/`send_indication`/`data_size`/`peer_listen` can also be set in the JSON config file. `--pcap` captures the traffic.

## Verifying that the peer receives the data

ChannelData and Send indications have no response, so by default only the local send is measured. With `--peer-listen ip:port`, sterak binds that UDP address and acts as the peer itself: each session sends a fresh random payload and records a `peer-receive-*` result whose latency is send → arrival at the peer. It fails if the exact payload (framing stripped, bytes unmodified) does not arrive within `--timeout`, naming any other datagrams the listener saw instead. `--peer` defaults to the bound address; set it explicitly when the TURN server reaches the listener under another address (NAT, wildcard bind such as `0.0.0.0:4000`).

```bash
./sterak turn --host turn.example.com:3478 --username alice --password s3cret --channel-data --send-indication --peer-listen 198.51.100.7:4000
```

# TURN malicious traffic

```bash
./sterak turn --host turn.example.com:3478 --runs 100 --concurrency 4 --scenario malicious
```

Each run opens a fresh UDP socket and sends one unauthenticated ChannelData message (random channel number in `0x4000`-`0x4fff`, `--data-size` random bytes) with no Allocate first. Per RFC 5766 §11.4 the server must silently discard it, so there is no reply: the reported `channel-data` latency is the local send time, and any reply that does arrive is ignored. No credentials are needed. `--scenario both` runs the legit scenario first, then the malicious one.
