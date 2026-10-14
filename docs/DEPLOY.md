# DEPLOY.md — Deploy do containerRust

> Como empacotar, configurar e operar o `containerRust` em substituição ao
> container Node. O contrato de sessão é compatível: o mesmo `db/{key}` e o mesmo
> Redis podem ser reutilizados sem novo QR.

## 1. Pré-requisitos

- Rust toolchain (edition 2021+).
- MariaDB/MySQL (`Instances`) e Redis acessíveis.
- RabbitMQ (opcional; o boot degrada sem ele).
- FFmpeg no PATH (mídia: thumbnails de vídeo, PTT/MP3, waveform).
- `libopus_mlow` disponível para calls (o `baileys-call` tem fallback se ausente).

## 2. Variáveis de ambiente

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `PORT` | `3000` | Porta HTTP |
| `BEAREAR_TOKEN` | — | Token global (validado se `BEAREAR_TOKEN_STRICT=true`) |
| `BEAREAR_TOKEN_STRICT` | `false` | Ativa validação do token global |
| `DB_ROOT` | `db` | Diretório das sessões SQLite (`db/{key}/db.sqlite`) |
| `DB_DIALECT` | `mysql` | `mysql` ou `sqlite` |
| `DB_HOST` | `mariadb` | Host do banco |
| `DB_PORT` | `3306` | Porta do banco |
| `DB_USER` | `root` | Usuário |
| `DB_PASSWORD` | — | Senha |
| `DB_NAME` | `wizy` | Nome do banco |
| `DATABASE` / `CONTEINER_ID` | — | Identificador do container (coluna `conteiner`) |
| `REDIS_URL` | `redis://:{DB_PASSWORD}@redis:6379` | URL do Redis |
| `RABBITMQ_URL` | `amqp://localhost` | URL do RabbitMQ |
| `WEBHOOK_CIRCUIT_FAILURES` | `5` | Falhas para abrir o circuito |
| `WEBHOOK_CIRCUIT_TIMEOUTS` | `2` | Timeouts para abrir o circuito |
| `WEBHOOK_CIRCUIT_OPEN_MS` | `90000` | Duração do circuito aberto |
| `WEBHOOK_TIMEOUT_MS` | `5000` | Timeout do POST no webhook |

## 3. Build

```bash
# Check rápido
cargo check --manifest-path containerRust/Cargo.toml

# Build release
cargo build --manifest-path containerRust/Cargo.toml --release
# binário: containerRust/target/release/container-rust
```

## 4. Execução

```bash
cd containerRust
# copie .env conforme o item 2
PORT=3000 DB_ROOT=/data/db ./target/release/container-rust
```

O boot é **tolerante**:

- MySQL fora → sobe com pool lazy (rotas de banco degradadas) e reconecta por
  chamada (`Db::connect`/`dummy`).
- Redis fora → `get`/`set`/`del` degradam para `None`/`false` sem derrubar a rota.
- RabbitMQ fora → filas pulam; `enqueue` é no-op até o próximo boot/consumidor.

## 5. Swap de sessão Node → Rust (sem QR)

1. Mantenha o **mesmo** `DB_ROOT` (SQLite) e o **mesmo** Redis do container Node.
2. Pare o container Node da instância **sem logout**.
3. Suba o `containerRust` apontando para os mesmos volumes.
4. O Rust lê `creds` do SQLite (`auth_data`) e as chaves de sinal do Redis
   (`auth:{key}:{category}-{id}`), reconecta e continua operando sem novo QR.

Critério de aceite automatizado:

```bash
cargo test --manifest-path containerRust/Cargo.toml --test session_swap
```

## 6. Operação e observabilidade

- Logs via `tracing` (`RUST_LOG=info` por padrão; `RUST_LOG=debug` para detalhe).
- Health: `GET /health` → `{ "status": "up" }`.
- RabbitMQ DLQ: `${DATABASE}_webhook_dlq` (capped, drop-head) para inspeção de
  falhas de webhook (timeout/5xx).

## 7. Regras do repositório

- Alterações de código começam em `containerRust/src/` e passam por
  `cargo check`/`cargo test`.
- **Nunca** editar `manager/`, `container/` ou `Hineken/` (somente leitura).
- A spec de sessão é imutável sem atualizar `docs/SESSION_FORMAT.md` e o teste
  de swap.
