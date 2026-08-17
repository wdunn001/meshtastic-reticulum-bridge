# meshtastic-reticulum-bridge

A small, self-contained **two-way** bridge between a **Meshtastic** mesh and a
**Reticulum / LXMF** network. It subscribes to a Meshtastic **MQTT** feed,
decodes the standard Meshtastic protobufs, and:

- **Meshtastic → Reticulum:** forwards text messages into Reticulum as LXMF,
  delivered to an address you choose. Positions and node-info are logged to
  SQLite for a future map.
- **Reticulum → Meshtastic:** re-encrypts inbound LXMF messages (anything sent
  to the bridge's own LXMF address) as Meshtastic packets and publishes them to
  the channel's MQTT downlink topic, so a gateway node rebroadcasts them onto
  the LoRa mesh.

Design notes:

- **No serial grab.** It reads from MQTT, so it never touches the node's USB /
  serial port. It runs happily alongside anything else that already owns the
  serial (an ATAK / OpenTAKServer gateway, the Meshtastic app, etc.).
- **Standalone Reticulum instance.** It joins Reticulum with its own identity and
  interfaces, so it doesn't need (and deliberately avoids) an `rnsd` "shared
  instance" — that path silently drops inbound LXMF for a separate identity.
- **Loop-safe.** Every packet the bridge injects is tagged; when the gateway
  re-uplinks it to MQTT, the bridge recognizes its own packet id (and virtual
  node number) and drops it instead of forwarding it back into Reticulum.
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
- **Uplink enabled:** on
- **Downlink enabled:** on (this is what lets the return path reach the mesh; see
  [Two-way / downlink](#two-way--downlink) below)
- Leave the default **root topic** `msh` and your region; keep the channel's
  *MQTT* enabled.

Within a few seconds of a text message on that channel, it's delivered over
Reticulum to `TARGET_LXMF_HASH`. Send an LXMF message back to the bridge's own
address (printed at startup and on `/api/status` as `lxmf_address`) and it lands
on the mesh. `docker compose logs -f bridge` shows the flow; a small status page
is served on `LISTEN_PORT` (default `8212`).

## Two-way / downlink

The return path (Reticulum → Meshtastic) is **on by default**. Two things make it
work:

1. **A gateway with Downlink enabled.** The bridge publishes an encrypted
   Meshtastic packet to the channel's MQTT topic; a Meshtastic node acting as the
   MQTT gateway only rebroadcasts it onto LoRa if that channel has **Downlink
   enabled**. This is a node-side setting the bridge can't set for you, and it's
   off by default in Meshtastic.
2. **The channel key + topic.** To publish a packet the mesh will accept, the
   bridge encrypts with the channel's key and publishes to the right topic. For
   the **default channel** everything is auto-learned from the uplink traffic it
   already sees (the public default key, the channel hash, and the
   `msh/<REGION>/2/e/<CHANNEL>` topic prefix), so no extra config is needed. For a
   **custom-PSK channel**, set `DOWNLINK_PSK` (and optionally `DOWNLINK_CHANNEL` /
   `DOWNLINK_TOPIC_PREFIX`).

Inbound LXMF is broadcast to the channel, prefixed with the sender's LXMF display
name, e.g. `[alice] on my way`. To turn the return path off entirely and run
uplink-only, set `ENABLE_DOWNLINK=false`.

Test it without a radio: `curl -XPOST localhost:8212/api/test/downlink` publishes
a real downlink packet through the exact encrypt-and-publish path (check
`/api/downlink`). With a gateway online and Downlink enabled, it hits the mesh.

## Configuration

All via environment (see `.env.example`):

| var | required | default | meaning |
|-----|----------|---------|---------|
| `TARGET_LXMF_HASH` | **yes** | – | LXMF destination that receives Meshtastic messages |
| `PROPAGATION_NODE_HASH` | no | – | LXMF propagation node for store-and-forward |
| `MQTT_HOST` / `MQTT_PORT` | no | `127.0.0.1` / `1883` | broker to subscribe to |
| `MQTT_USERNAME` / `MQTT_PASSWORD` | no | anonymous | broker auth (blank = anonymous) |
| `MQTT_TOPIC_ROOT` | no | `msh` | topic prefix your node publishes under |
| `DISPLAY_NAME` / `LISTEN_PORT` | no | `Meshtastic Bridge` / `8212` | LXMF display name + status HTTP port |
| `ENABLE_DOWNLINK` | no | `true` | Reticulum → Meshtastic return path |
| `DOWNLINK_CHANNEL` | no | `LongFast` | channel to inject into (its key/hash/topic are auto-learned) |
| `DOWNLINK_PSK` | no | default channel key | 32-hex-char AES-128 key for a custom-PSK channel |
| `DOWNLINK_TOPIC_PREFIX` | no | auto-learned | `msh/<REGION>/2/e/<CHANNEL>`; set to publish before any uplink is seen |
| `DOWNLINK_CHANNEL_HASH` | no | auto-learned | 1-byte channel hash, if you'd rather pin it |
| `DOWNLINK_HOP_LIMIT` | no | `3` | hop limit stamped on injected packets |
| `DOWNLINK_MAX_BYTES` | no | `200` | truncate injected text to this many bytes |
| `BRIDGE_NODE_NUM` | no | derived from RNS identity | virtual Meshtastic node number the bridge injects as |

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

**v2 is two-way** for **channel broadcast**: text flows Meshtastic → LXMF, and
inbound LXMF is broadcast back onto the Meshtastic channel. Positions / node-info
are recorded but not yet surfaced on a map. Direct-message mapping (round-tripping
a Reticulum DM to a specific Meshtastic node num, and vice-versa) is the natural
next step and is **not** implemented yet. Contributions welcome.

## Why a custom bridge

Existing projects didn't fit a headless "read MQTT, forward to a plain LXMF
destination" job: **FreeTAKTeam/Reticulum_Meshtastic_Integration** is built around
FreeTAK's Reticulum Community Hub topic model rather than a single LXMF delivery
address, and **Colorado-Mesh/mesh-client** is an Electron desktop client, not a
service. The decode-and-forward logic here is small enough that a focused
container was the pragmatic choice.

## License

MIT — see [LICENSE](LICENSE).
