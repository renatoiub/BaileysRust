# API_COMPAT.md — Paridade de API entre containerRust e o container Node

> O `containerRust` expõe a **mesma superfície HTTP** do container Node
> (`container/src/routes/index.ts`), porta 3000. Este documento mapeia cada rota
> e destaca diferenças intencionais.

## 1. Formato de resposta

Todas as rotas usam o shape `retorno` do Node:

```json
{ "error": false, "message": null, "retorno": { ... } }
```

- Erros: `{ "error": true, "message": "...", "retorno": null }` com status
  correspondente (`400`, `403`, `404`, `500`).

## 2. Autenticação

| Header | Uso |
|--------|-----|
| `Authorization: Bearer <token>` | `verifyToken` (instância) e webhooks |

- `BEAREAR_TOKEN` (global) é validado **apenas** com `BEAREAR_TOKEN_STRICT=true`
  (o Node mantém a checagem comentada; mantemos a paridade).
- O `bearear_token` da instância é validado em `isSessionOnline`.

## 3. Rotas

### 3.1 `/instances`

| Rota | Body | Descrição |
|------|------|-----------|
| `POST /instances/list` | — | Lista instâncias ativas |
| `POST /instances/create` | `{ key, events?, ignoreGroups? }` | Cria/conecta instância |
| `POST /instances/remove` | `{ key, force? }` | Logout + remove creds |
| `POST /instances/qr` | `{ key }` | Retorna HTML com QR (data URL SVG) |
| `POST /instances/scanQr` | `{ key, qr }` | Completa pareamento via QR string |
| `POST /instances/logout` | `{ key }` | Desconecta e limpa sessão |
| `POST /instances/info` | `{ key }` | `InstanceData` (jid, lid, status, webhook...) |
| `POST /instances/edit` | `{ key, ...campos }` | Atualiza campos da instância |
| `POST /instances/flushCache` | `{ key }` | Limpa cache da instância |
| `POST /instances/migrate` | `{ key, ... }` | Migração de instância |

### 3.2 `/messages`

| Rota | Body | Descrição |
|------|------|-----------|
| `POST /messages/sendMessage` | `{ key, jid, type, content?, caption?, url?... }` | Texto/mídia |
| `POST /messages/editMessage` | `{ key, jid, messageId, content }` | Edita mensagem |
| `POST /messages/deleteMessage` | `{ key, jid, messageId }` | Apaga (para todos) |
| `POST /messages/reactMessage` | `{ key, jid, messageId, emoji }` | Reação |
| `POST /messages/sendList` | `{ key, jid, ... }` | Mensagem de lista |
| `POST /messages/sendLocation` | `{ key, jid, lat, lng }` | Localização |
| `POST /messages/sendLinkPreview` | `{ key, jid, url, title?, description?, thumbnailUrl? }` | Link preview |
| `POST /messages/ForwardMessage` | `{ key, jid, forwardId }` | Encaminha |
| `POST /messages/SendContact` | `{ key, jid, contactName, contactNumber }` | Contato |
| `POST /messages/sendButton/{tipo}` | `{ key, jid, text?, footer?, header?, bizNode?, ... }` | **Só Rust** (experimental). `tipo`: `buttons`, `template`, `list`, `interactive`, `quick_reply`, `cta_url`, `cta_copy`, `cta_call`, `single_select`, `carousel`, `pix`, `pay`, `shop`, `collection`, `catalog`, `location_request`, `webview`, e mídia + texto + botões em `image`, `video`, `document`, `location` (`format`: `interactive` padrão, `buttons` ou `template`). Builders em `baileys_socket::interactive`; `bizNode` = `padrao` (padrão), `simples` ou `none` |

### 3.3 `/misc`

| Rota | Body | Descrição |
|------|------|-----------|
| `POST /misc/onWhatsapp` | `{ key, jid }` | Verifica existência |
| `POST /misc/getProfilePicture` | `{ key, jid }` | Foto de perfil |
| `POST /misc/updateProfilePicture` | `{ key, jid, url }` | Atualiza foto |
| `POST /misc/block` | `{ key, jid, status }` | Bloqueia/desbloqueia |
| `POST /misc/getcustomStatus` | `{ key, jid }` | Status customizado |
| `POST /misc/UpdateMyStatus` | `{ key, status }` | Atualiza próprio status |
| `POST /misc/readMessages` | `{ key, jid, readMessages }` | Marca como lidas |
| `POST /misc/getContacts` | `{ key }` | Lista contatos |
| `POST /misc/getMessage` | `{ key, jid, messageId }` | Busca mensagem |

### 3.4 `/groups`

| Rota | Body | Descrição |
|------|------|-----------|
| `POST /groups/all` | `{ key }` | Todos os grupos |
| `POST /groups/getAlGroups` | `{ key }` | Todos os grupos (variante) |
| `POST /groups/getInfo` | `{ key, jid }` | Metadados do grupo |
| `POST /groups/create` | `{ key, name, participants }` | Cria grupo |
| `POST /groups/leave` | `{ key, jid }` | Sai do grupo |
| `POST /groups/participants` | `{ key, jid, participants?, action? }` | Add/remove/promote/demote |
| `POST /groups/admins` | `{ key, jid }` | Lista admins |
| `POST /groups/updateSettings` | `{ key, jid, ... }` | Configurações |
| `POST /groups/update` | `{ key, jid, ... }` | Assunto/descrição |
| `POST /groups/updatePicture` | `{ key, jid, url }` | Foto do grupo |
| `POST /groups/getInfoUrl` | `{ key, url }` | Info por link de convite |
| `POST /groups/joinFromUrl` | `{ key, url }` | Entra via link |
| `POST /groups/getGrouopUrl` | `{ key, jid }` | Link de convite |
| `POST /groups/flush` | `{ key }` | Limpa cache de grupos |
| `POST /groups/getAllNews` | `{ key }` | Newsletters |

### 3.5 `/calls`

| Rota | Body/Query | Descrição |
|------|-----------|-----------|
| `POST /calls/RejectCall` | `{ key, callId }` | Rejeita chamada |
| `POST /calls/token` | `{ key }` | Cria call token |
| `GET /calls/token` | `?key=` | Obtém call token |

## 4. Diferenças intencionais

1. **Eventos webhook**: mesmo payload do Node (`qrCodeUpdate`, `messagesUpsert`,
   `connectionUpdate`), mas roteados pelo RabbitMQ Rust (`lapin`) em vez do
   `amqplib`.
2. **SQLx vs Sequelize**: `Instances` model mapeia as mesmas colunas; consulta por
   `conteiner = DATABASE`.
3. **Redis**: mesmo contrato `auth:{key}:{category}-{id}` sem TTL; o `connection-manager`
   é gerenciado pelo crate `redis` (degradação graciosa se indisponível).
4. **QR**: renderizado como SVG data-URL (mesmo HTML do Node).
5. **`retorno`** mantém `error`/`message`/`retorno`; status HTTP pode divergir
   minimamente do Express em casos de borda (documentados por teste).
6. **`/messages/sendButton/{tipo}`** existe só no Rust: o Node não tem rotas de
   botões. O nó `<biz>` é anexado no relay (`RelaySendJob.biz_node`) e a
   detecção desembrulha `viewOnce*`/`ephemeral`/`deviceSent`.

## 5. Contrato de sessão (swap sem QR)

Ver [SESSION_FORMAT.md](SESSION_FORMAT.md) §6. O teste de swap em
`containerRust/tests/session_swap.rs` valida:

- leitura de `creds` gravados pelo Node (camelCase + BufferJSON);
- roundtrip de serialização;
- formato das chaves Redis.

Se um desses testes falhar, o swap Node ↔ Rust **não** é seguro.
