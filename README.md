# Pratu

**Pratu** (ประตู, Thai for "door") is a headless, multi-tenant authentication server and OAuth2/OIDC provider, inspired by the [Ory](https://www.ory.sh) ecosystem.

> ⚠️ Early development. Nothing here is ready for production use.

## Design in one paragraph

Each **tenant** is a fully isolated identity namespace — its own end-users, JSON-Schema-defined identity traits, OAuth2 clients, signing keys, and configuration — addressed by its own hostname (`{slug}.{base_domain}`, custom domains later) and therefore its own OIDC issuer. The server is headless: login, registration, recovery, and verification are self-service flows exposed as JSON; tenants bring their own UI, including for OAuth2 login/consent (Hydra-style challenges). Passwords are the first factor; TOTP and SMS one-time codes are second factors. Postgres is the only datastore.

The vocabulary lives in [CONTEXT.md](CONTEXT.md); load-bearing decisions live in [docs/adr](docs/adr).

## Development

Requires Go 1.26+ and Docker.

```sh
cp pratu.example.yaml pratu.yaml
make db-up          # start Postgres
make migrate        # apply migrations
make run            # public API :4433, admin API :4434
```

```sh
curl http://localhost:4433/health/ready
```

Tenant hostnames work locally without DNS setup: browsers and curl resolve `*.localhost` to `127.0.0.1`, so tenant `acme` lives at `http://acme.pratu.localhost:4433`.

## License

[Apache-2.0](LICENSE)
