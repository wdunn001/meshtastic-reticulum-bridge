# meshtastic-reticulum-bridge

A small, self-contained bridge that carries **Meshtastic** mesh traffic into a
**Reticulum / LXMF** network. It subscribes to a Meshtastic **MQTT** feed,
decodes the standard Meshtastic protobufs, and forwards text messages into
Reticulum as LXMF messages delivered to an address you choose. Positions and
node-info are logged to SQLite for a future map.

- **No serial grab.** It reads from MQTT, so it never touches the node's USB /
  serial port. It runs happily alongside anything else that already owns the
  serial (an ATAK / OpenTAKServer gateway, the Meshtastic app, etc.).
- **Standalone Reticulum instance.** It joins Reticulum with its own identity and
  interfaces, so it doesn't need (and deliberately avoids) an `rnsd` "shared
  instance" — that path silently drops inbound LXMF for a separate identity.
- **Batteries included.** The compose file ships a Mosquitto broker; point a
  Meshtastic node at it and go.

## Quick start

```sh
git clone https://github.com/wdunn001/meshtastic-reticulum-bridge
cd meshtastic-reticulum-bridge
cp .env.example .env
# edit .env: set TARGET_LXMF_HASH to the LXMF destination that should receive the
# messages (e.g. your Sideband / NomadNet / MeshChat identity, 32 hex chars)
docker compose up -d --build
```

Then, on your **Meshtastic node** (app or web UI), under *MQTT*:
- **Server:** `THIS_HOST:1883` (the machine running this stack)
- **Uplink enabled:** on (Downlink optional — this bridge is one-way for now)
- Leave the default **root topic** `msh` and your region; keep the channel's
  *MQTT / uplink* enabled.

Within a few seconds of a text message on that channel, it's delivered over
Reticulum to `TARGET_LXMF_HASH`. `docker compose logs -f bridge` shows the flow;
a small status page is served on `LISTEN_PORT` (default `8212`).

## Configuration

All via environment (see `.env.example`):

| var | required | default | meaning |
|-----|----------|---------|---------|
| `TARGET_LXMF_HASH` | **yes** | – | LXMF destination that receives the messages |
| `PROPAGATION_NODE_HASH` | no | – | LXMF propagation node for store-and-forward |
| `MQTT_HOST` / `MQTT_PORT` | no | `127.0.0.1` / `1883` | broker to subscribe to |
| `MQTT_USERNAME` / `MQTT_PASSWORD` | no | anonymous | broker auth (blank = anonymous) |
| `MQTT_TOPIC_ROOT` | no | `msh` | topic prefix your node publishes under |
| `DISPLAY_NAME` / `LISTEN_PORT` | no | `Meshtastic Bridge` / `8212` | LXMF display name + status HTTP port |

### Using your own broker instead of the bundled one
Set `MQTT_HOST`/`MQTT_PORT`/`MQTT_USERNAME`/`MQTT_PASSWORD` (and `MQTT_TOPIC_ROOT`
to whatever your node publishes to), and you can drop the `mosquitto` service from
`docker-compose.yml`.

### Reticulum interfaces
`config/rns-config` defaults to a LAN `AutoInterface` (IPv6 link-local multicast),
so it peers with any Reticulum node on the same LAN. To reach the wider network
without local multicast, uncomment the `TCPClientInterface` backstop in that file
and point it at a transport node you trust.

## Status

**v1 is one-way** (Meshtastic → Reticulum): text messages flow into the LXMF
network; positions / node-info are recorded but not yet surfaced, and there's no
return path onto the Meshtastic mesh. Contributions welcome.

## Why a custom bridge

Existing projects didn't fit a headless "read MQTT, forward to a plain LXMF
destination" job: **FreeTAKTeam/Reticulum_Meshtastic_Integration** is built around
FreeTAK's Reticulum Community Hub topic model rather than a single LXMF delivery
address, and **Colorado-Mesh/mesh-client** is an Electron desktop client, not a
service. The decode-and-forward logic here is small enough that a focused
container was the pragmatic choice.

## License

MIT — see [LICENSE](LICENSE).
