# Omniston Resolver Client in C (`v1beta8`)

STON.fi Omniston resolver client in pure C (`nghttp2` + `OpenSSL`). Bring your own pricing engine and settlement executor.

Built by **[WebMesh](https://webmesh.cc)**.

- Zero heap allocations on the RFQ quote and event parsing paths
- gRPC over HTTP/2 + TLS (`ResolverRpc/Open` bidi stream), auto-reconnect
- Ed25519 auth, `SignResolverAddress` caching and refresh
- Tested live, including end-to-end TON Escrow settlement

## Build

```bash
# deps: build-essential libnghttp2-dev libssl-dev
make        # ./resolver      (solver_adapter.c)
make demo   # ./resolver_demo (solver_demo.c)
```

macOS: `brew install nghttp2 openssl@3`, then pass their include/lib paths via `CFLAGS` / `LDFLAGS`.

## Run

```bash
export OMNISTON_KEYS_PATH=./resolver_keys.json   # {"publicKey":"<64-hex>","privateKey":"<64|128-hex>"}
export OMNISTON_STAKE_ADDRESS=EQ...              # Resolver Stake SBT
export OMNISTON_RESOLVER_ADDRESS=EQ...           # trading wallet
export OMNISTON_GRPC_ENDPOINT=omni-grpc-sandbox.ston.fi:443

# optional
export OMNISTON_PROTOCOL_CONTRACT=EQ...          # pre-warm signature
export OMNISTON_EVM_ADDRESS=0x...                # cross-chain legs
export OMNISTON_IDLE_TIMEOUT_S=120

./resolver
```

Never commit key files or `.env`.

## Integrate

**Pricing** (`solver_adapter.c`): return `0` to quote, non-zero to decline. Amounts are raw units, `unsigned __int128`.

```c
int solver_quote(const rfq_t *rfq, u128 *receives, u128 *sends);
```

**Settlement** (`escrow.h`): hook order and execution events into your wallet or signer.

```c
escrow_hooks_t hooks = {
    .on_order     = my_on_order,
    .on_execution = my_on_execution,
    .on_closed    = my_on_closed,
    .on_signed    = my_on_signed,
};
escrow_init(esc_log, &hooks);
```

## TON Escrow Reference

Fulfilling an intrachain order on `StonfiEscrowFactory` (`src_protocol_contract`):

- **Jetton:** `jetton_transfer` (`0x0f8a7ea5`) to `src_protocol_contract`, `forward_payload = Right ^UnlockPayload`
- **TON:** pTON v2 `ton_transfer` (`0x01f3835d`) to the factory's pTON wallet (`dst_wrapped_native` / `src_wrapped_native`), `forward_payload = ^UnlockPayload`

```text
StonfiEscrowFactoryUnlockPayload       0xd55df9d2
  quoteId:uint256 excesses:MsgAddress extraFields:^Cell unlockArgs:^Cell forwardParams:Maybe ^Cell

StonfiEscrowFactoryBilateralUnlockArgs 0x0bdb581e
  minOut:Coins ignoreRefundAmount:Coins signed:Maybe BilateralSignPayload
```

`signed` takes the signature and `validity_deadline` from `ResolverAddressSignedEvent`.

## Mock Testing

Needs `grpcio grpcio-tools cryptography`, [`stonfi-proto`](https://github.com/ston-fi/stonfi-proto) and throwaway keys.

```bash
git clone https://github.com/ston-fi/stonfi-proto
P=$PWD/stonfi-proto/proto
mkdir -p mock/gen
python3 -m grpc_tools.protoc -I"$P" --python_out=mock/gen --grpc_python_out=mock/gen \
    $(cd "$P" && find stonfi/omni/v1beta8 stonfi/common -name '*.proto')

python3 mock/mock_escrow.py &
OMNISTON_INSECURE=1 \
OMNISTON_GRPC_ENDPOINT=127.0.0.1:50552 \
OMNISTON_KEYS_PATH=./test_keys.json \
OMNISTON_STAKE_ADDRESS=EQ_TEST_STAKE \
OMNISTON_RESOLVER_ADDRESS=EQ_TEST_RESOLVER \
OMNISTON_PROTOCOL_CONTRACT=EQ_TEST_PROTOCOL \
./resolver_demo
```

## Layout

```text
omniston_resolver.c   transport, auth, RFQ dispatch
pb.h, pbtypes.h       protobuf reader/writer, codecs
solver.h              pricing interface
solver_adapter.c      your pricing engine (template)
solver_demo.c         toy 0.3% fee solver
escrow.h, escrow.c    event parsers, order table, signature cache
mock/                 Python mock servers
```

## License

[MIT](LICENSE)
