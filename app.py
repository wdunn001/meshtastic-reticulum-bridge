"""meshtastic-reticulum-bridge -- two-way (v2) Meshtastic <-> Reticulum/LXMF bridge.

Uplink (Meshtastic -> Reticulum): subscribes (read-only) to a Meshtastic MQTT
feed, decodes the standard Meshtastic protobufs (ServiceEnvelope), forwards
TEXT_MESSAGE_APP packets into Reticulum as LXMF messages delivered to a
configured destination, and records POSITION_APP / NODEINFO_APP packets to local
SQLite (for a future unified map). It reads from MQTT, so it never grabs the
node's serial port -- it can run alongside any other tool (e.g. an
ATAK/OpenTAKServer gateway) that already owns the serial.

Downlink (Reticulum -> Meshtastic): inbound LXMF messages addressed to the
bridge's own delivery destination are re-encrypted as Meshtastic packets and
published to the channel's MQTT downlink topic (msh/REGION/2/e/CHANNEL/USERID),
so a gateway node with `Downlink enabled` rebroadcasts them onto the LoRa mesh.
The channel encryption key + hash + topic are auto-learned from observed uplink
traffic on DOWNLINK_CHANNEL (overridable via env). A packet-id + source-node
loop guard drops the echo of anything this bridge injected, so an injected
message that gets re-uplinked by the gateway is never re-forwarded.

RNS/LXMF side runs a STANDALONE RNS instance (its own config dir + identity) and
joins the network purely over its own interfaces (config/rns-config): by default
a LAN AutoInterface (IPv6 link-local multicast) so it peers with any local
Reticulum node, plus an optional TCP backstop. It deliberately does NOT ride an
rnsd "shared instance" RPC socket -- that path silently drops inbound LXMF for a
process with a genuinely separate identity/config dir, so standalone mode
sidesteps the whole class of bug.

Config is entirely via environment variables (see the compose file / .env):
TARGET_LXMF_HASH (required destination), optional PROPAGATION_NODE_HASH, the
MQTT_* settings, and the DOWNLINK_* settings (downlink is ON by default). The
bundled docker-compose ships a Mosquitto broker so you can point a Meshtastic
node's MQTT uplink straight at it.

RNS.Reticulum() must run on the process's main thread (installs signal
handlers). Same pattern as comms-web: uvicorn runs in a background thread,
RNS/MQTT init + the MQTT loop drive the main thread.
"""
import os
import sqlite3
import struct
import threading
import time
from collections import deque
from contextlib import contextmanager

import RNS
import LXMF
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from meshtastic.protobuf import mqtt_pb2, mesh_pb2, portnums_pb2

# --------------------------------------------------------------------------
# Config (env-driven; see docker-compose.yml)
# --------------------------------------------------------------------------
RNS_CONFIG_DIR = os.environ.get("RNS_CONFIG_DIR", "/config/rns")
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/config")
IDENTITY_PATH = os.environ.get("IDENTITY_PATH", "/config/identity/bridge_identity")
DB_PATH = os.environ.get("DB_PATH", "/config/app/state.db")
DISPLAY_NAME = os.environ.get("DISPLAY_NAME", "Meshtastic Bridge")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8212"))
PROPAGATION_NODE_HASH_ENV = os.environ.get("PROPAGATION_NODE_HASH", "").strip()
TARGET_LXMF_HASH_ENV = os.environ.get("TARGET_LXMF_HASH", "").strip()

MQTT_HOST = os.environ.get("MQTT_HOST", "127.0.0.1")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USERNAME = os.environ.get("MQTT_USERNAME", "")            # blank = anonymous
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD", "")           # inline (or use *_FILE)
MQTT_PASSWORD_FILE = os.environ.get("MQTT_PASSWORD_FILE", "") # optional secret file
# Meshtastic's default MQTT uplink publishes under "msh"; set this if your node
# (or an upstream like OpenTAKServer) uses a different topic root.
MQTT_TOPIC_ROOT = os.environ.get("MQTT_TOPIC_ROOT", "msh")

SYNC_INTERVAL_S = 300
APP_START_TS = time.time()

# Meshtastic's public default channel PSK (the 1-byte "AQ==" shorthand expands
# to this fixed AES-128 key in every open-source Meshtastic firmware build --
# this is NOT a secret, it's how the default/"LongFast" channel is readable by
# any compliant device with no pre-shared config; see meshtastic firmware
# `Channels::initDefaultChannel` / `Crypto::initNonce`). Packets on a channel
# using a custom PSK will fail to decrypt here and are recorded as opaque/
# encrypted -- this bridge only ever reads what the default channel already
# broadcasts in the clear-to-anyone-listening sense.
DEFAULT_PSK = bytes([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
])

# --- Downlink (Reticulum -> Meshtastic) -----------------------------------
# ON by default: inbound LXMF is re-encrypted and published to the channel's
# MQTT downlink topic for a gateway with `Downlink enabled` to rebroadcast.
ENABLE_DOWNLINK = os.environ.get("ENABLE_DOWNLINK", "true").strip().lower() in ("1", "true", "yes", "on")
# Channel to inject into. Its encryption key, channel hash, and topic prefix are
# auto-learned from observed uplink traffic whose ServiceEnvelope.channel_id
# matches this; the values below are only fallbacks / overrides.
DOWNLINK_CHANNEL = os.environ.get("DOWNLINK_CHANNEL", "LongFast")
# Explicit topic prefix "msh/<REGION>/2/e/<CHANNEL>" -- set this to publish
# before any uplink has been observed (otherwise it is learned on first packet).
DOWNLINK_TOPIC_PREFIX = os.environ.get("DOWNLINK_TOPIC_PREFIX", "").strip().rstrip("/")
DOWNLINK_HOP_LIMIT = int(os.environ.get("DOWNLINK_HOP_LIMIT", "3"))
DOWNLINK_MAX_BYTES = int(os.environ.get("DOWNLINK_MAX_BYTES", "200"))  # Meshtastic text payload cap
# Custom-channel overrides. DOWNLINK_PSK: 32-hex-char AES-128 key; blank = the
# public default-channel key above. DOWNLINK_CHANNEL_HASH: the 1-byte channel
# hash (decimal/hex); blank = learned from traffic, else computed.
_dpsk = os.environ.get("DOWNLINK_PSK", "").strip()
DOWNLINK_PSK = bytes.fromhex(_dpsk) if _dpsk else DEFAULT_PSK
_dch = os.environ.get("DOWNLINK_CHANNEL_HASH", "").strip()
DOWNLINK_CHANNEL_HASH = (int(_dch, 0) & 0xFF) if _dch else None
# The virtual Meshtastic node number the bridge injects as. Blank = derived
# stably from the RNS identity so it's consistent across restarts.
BRIDGE_NODE_NUM_ENV = os.environ.get("BRIDGE_NODE_NUM", "").strip()


def _pkt_from(packet) -> int:
    # MeshPacket's proto field is literally named "from" -- a reserved Python
    # keyword, so protoc does NOT expose it as `.from_` (confirmed live: that
    # raises AttributeError). Must go through getattr/setattr on the literal
    # name instead.
    return getattr(packet, "from")


def _pkt_set_from(packet, value: int):
    setattr(packet, "from", value)


def channel_hash(name: str, psk: bytes) -> int:
    """Meshtastic channel hash (firmware Channels::generateHash): xor of every
    byte of the channel *settings* name, xored with every byte of the psk.
    Note the default primary channel's settings name is "" (empty) even though
    its MQTT channel_id / display name is "LongFast" -- so a value LEARNED from
    real traffic is always preferred over this computed one."""
    h = 0
    for b in name.encode("utf-8"):
        h ^= b
    for b in psk:
        h ^= b
    return h & 0xFF


def decrypt_default_channel(packet) -> bytes | None:
    """Meshtastic AES-128-CTR with a nonce built from packet id + sender node
    (CryptoEngine::initNonce): 8 bytes = packet_id (u32 LE) + from (u32 LE),
    padded to a 16-byte IV with 8 zero bytes (the CTR counter)."""
    try:
        nonce = struct.pack("<II", packet.id, _pkt_from(packet)) + b"\x00" * 8
        cipher = Cipher(algorithms.AES(DEFAULT_PSK), modes.CTR(nonce))
        dec = cipher.decryptor()
        return dec.update(packet.encrypted) + dec.finalize()
    except Exception:
        return None


def encrypt_channel(packet_id: int, from_num: int, plaintext: bytes, psk: bytes) -> bytes:
    """Inverse of decrypt_default_channel -- same AES-128-CTR nonce scheme, used
    to build a downlink packet the mesh (and this bridge's own decrypt path)
    will accept."""
    nonce = struct.pack("<II", packet_id, from_num) + b"\x00" * 8
    cipher = Cipher(algorithms.AES(psk), modes.CTR(nonce))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


# --------------------------------------------------------------------------
# SQLite state -- bridged messages + node positions/names, short-lived
# connections per call (same pattern as reticulum-web-stack).
# --------------------------------------------------------------------------
_db_lock = threading.Lock()


@contextmanager
def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with _db_lock:
            yield conn
            conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY, long_name TEXT, short_name TEXT, last_seen REAL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS positions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT, lat REAL, lon REAL,
            alt REAL, ts REAL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS bridged_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT, text TEXT,
            lxmf_state TEXT, mqtt_topic TEXT, ts REAL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS downlink_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, source_hash TEXT, sender TEXT,
            text TEXT, state TEXT, mqtt_topic TEXT, ts REAL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS mqtt_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT, portnum TEXT,
            decoded INTEGER, note TEXT, ts REAL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_positions_node ON positions(node_id, ts)")


def upsert_node(node_id, long_name=None, short_name=None):
    with db() as conn:
        row = conn.execute("SELECT node_id FROM nodes WHERE node_id=?", (node_id,)).fetchone()
        if row:
            conn.execute(
                "UPDATE nodes SET last_seen=?, long_name=COALESCE(?, long_name), "
                "short_name=COALESCE(?, short_name) WHERE node_id=?",
                (time.time(), long_name, short_name, node_id))
        else:
            conn.execute(
                "INSERT INTO nodes (node_id, long_name, short_name, last_seen) VALUES (?,?,?,?)",
                (node_id, long_name, short_name, time.time()))


def record_position(node_id, lat, lon, alt):
    with db() as conn:
        conn.execute("INSERT INTO positions (node_id, lat, lon, alt, ts) VALUES (?,?,?,?,?)",
                      (node_id, lat, lon, alt, time.time()))


def record_bridged_message(node_id, text, state, topic):
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO bridged_messages (node_id, text, lxmf_state, mqtt_topic, ts) VALUES (?,?,?,?,?)",
            (node_id, text, state, topic, time.time()))
        return cur.lastrowid


def update_bridged_state(row_id, state):
    with db() as conn:
        conn.execute("UPDATE bridged_messages SET lxmf_state=? WHERE id=?", (state, row_id))


def record_downlink(source_hash, sender, text, state, topic):
    with db() as conn:
        conn.execute(
            "INSERT INTO downlink_messages (source_hash, sender, text, state, mqtt_topic, ts) "
            "VALUES (?,?,?,?,?,?)",
            (source_hash, sender, text, state, topic, time.time()))


def record_mqtt(topic, portnum, decoded, note=""):
    with db() as conn:
        conn.execute(
            "INSERT INTO mqtt_log (topic, portnum, decoded, note, ts) VALUES (?,?,?,?,?)",
            (topic, portnum, 1 if decoded else 0, note, time.time()))


# --------------------------------------------------------------------------
# RNS / LXMF state
# --------------------------------------------------------------------------
class RNSState:
    reticulum = None
    identity = None
    router = None
    delivery_destination = None
    lxmf_address = None
    ready = False
    error = None
    target_hash = None  # resolved bytes of TARGET_LXMF_HASH_ENV
    target_resolved = False  # whether we've ever seen an announce/path for it
    last_send_ts = None
    last_send_state = None
    mqtt_connected = False
    mqtt_error = None
    mqtt_client = None
    inbound_count = 0
    outbound_count = 0
    # downlink (Reticulum -> Meshtastic)
    bridge_node_num = None       # virtual Meshtastic node number we inject as
    downlink_topic_base = None   # learned "msh/<REGION>/2/e/<CHANNEL>"
    downlink_channel_hash = None # learned MeshPacket.channel byte for the channel
    downlink_count = 0
    last_downlink_ts = None
    last_downlink_state = None
    last_inbound_lxmf_ts = None
    injected_order = deque(maxlen=1024)  # packet ids we published, for the loop guard


S = RNSState()


def _sender_label(source_hash: bytes) -> str:
    """Best-effort human label for an inbound LXMF sender: the announced LXMF
    display name if we've seen their announce, else a short hash prefix."""
    hexh = RNS.hexrep(source_hash, delimit=False)
    try:
        app_data = RNS.Identity.recall_app_data(source_hash)
        if app_data:
            name = LXMF.display_name_from_app_data(app_data)
            if name:
                return name.strip()[:20]
    except Exception:
        pass
    return hexh[:8]


def _on_lxmf_delivery(message):
    """Inbound LXMF (a message addressed to the bridge's OWN delivery
    destination) -> Meshtastic downlink. With ENABLE_DOWNLINK on, the message
    text is re-encrypted and published to the channel's MQTT downlink topic for
    a gateway with Downlink enabled to rebroadcast onto LoRa."""
    S.last_inbound_lxmf_ts = time.time()
    try:
        text = message.content.decode("utf-8", errors="replace") if message.content else ""
    except Exception:
        text = ""
    src = RNS.hexrep(message.source_hash, delimit=False)

    if not ENABLE_DOWNLINK:
        RNS.log(f"meshtastic-bridge: inbound LXMF from {src} (downlink disabled, not relayed)",
                RNS.LOG_NOTICE)
        record_downlink(src, _sender_label(message.source_hash), text, "downlink-disabled", "")
        return

    if not text.strip():
        record_downlink(src, _sender_label(message.source_hash), text, "empty-ignored", "")
        return

    label = _sender_label(message.source_hash)
    state, topic = send_meshtastic_text(text.strip(), sender_label=label)
    record_downlink(src, label, text.strip(), state, topic)
    RNS.log(f"meshtastic-bridge: inbound LXMF from {src} -> mesh downlink [{state}]", RNS.LOG_NOTICE)


def init_rns():
    init_db()
    os.makedirs(RNS_CONFIG_DIR, exist_ok=True)
    try:
        S.reticulum = RNS.Reticulum(configdir=RNS_CONFIG_DIR)
    except Exception as e:
        S.error = f"Reticulum init failed: {e}"
        RNS.log(f"meshtastic-bridge: {S.error}", RNS.LOG_ERROR)
        return

    os.makedirs(os.path.dirname(IDENTITY_PATH), exist_ok=True)
    if os.path.isfile(IDENTITY_PATH):
        S.identity = RNS.Identity.from_file(IDENTITY_PATH)
    else:
        S.identity = RNS.Identity()
        S.identity.to_file(IDENTITY_PATH)

    # Stable virtual Meshtastic node number for downlink injection.
    if BRIDGE_NODE_NUM_ENV:
        S.bridge_node_num = int(BRIDGE_NODE_NUM_ENV, 0) & 0xFFFFFFFF
    else:
        S.bridge_node_num = int.from_bytes(S.identity.hash[:4], "big") | 0x1
    if S.bridge_node_num in (0x00000000, 0xFFFFFFFF):
        S.bridge_node_num ^= 0x1

    os.makedirs(STORAGE_DIR, exist_ok=True)
    S.router = LXMF.LXMRouter(identity=S.identity, storagepath=STORAGE_DIR)
    S.delivery_destination = S.router.register_delivery_identity(S.identity, display_name=DISPLAY_NAME)
    S.router.register_delivery_callback(_on_lxmf_delivery)
    S.lxmf_address = RNS.hexrep(S.delivery_destination.hash, delimit=False)

    if PROPAGATION_NODE_HASH_ENV:
        try:
            S.router.set_outbound_propagation_node(bytes.fromhex(PROPAGATION_NODE_HASH_ENV))
        except Exception as e:
            RNS.log(f"meshtastic-bridge: bad PROPAGATION_NODE_HASH: {e}", RNS.LOG_ERROR)

    if TARGET_LXMF_HASH_ENV:
        try:
            S.target_hash = bytes.fromhex(TARGET_LXMF_HASH_ENV)
            RNS.Transport.request_path(S.target_hash)
        except Exception as e:
            RNS.log(f"meshtastic-bridge: bad TARGET_LXMF_HASH: {e}", RNS.LOG_ERROR)

    S.delivery_destination.announce()
    S.ready = True
    RNS.log(f"meshtastic-bridge: ready, LXMF address {S.lxmf_address}, "
            f"downlink {'ON' if ENABLE_DOWNLINK else 'OFF'} as node {_node_hex(S.bridge_node_num)}",
            RNS.LOG_NOTICE)

    while True:
        time.sleep(SYNC_INTERVAL_S)
        if S.target_hash and RNS.Identity.recall(S.target_hash) is None:
            RNS.Transport.request_path(S.target_hash)


def send_lxmf_text(node_id: str, text: str, topic: str):
    """Forward one Meshtastic text message into Reticulum as an LXMF message
    to the pinned TARGET_LXMF_HASH. Direct if the recipient's identity is known
    (prior announce/path), else propagated via the pinned lxmd node."""
    if not S.ready or S.target_hash is None:
        record_bridged_message(node_id, text, "no-target-configured", topic)
        return

    row_id = record_bridged_message(node_id, text, "sending", topic)
    ident = RNS.Identity.recall(S.target_hash)
    if ident is None:
        RNS.Transport.request_path(S.target_hash)
        update_bridged_state(row_id, "target-identity-unknown-path-requested")
        return

    destination = RNS.Destination(ident, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
    pn = S.router.get_outbound_propagation_node() if S.router else None
    method = LXMF.LXMessage.DIRECT if (RNS.Transport.has_path(S.target_hash) or pn is None) else LXMF.LXMessage.PROPAGATED

    title = f"Meshtastic: {node_id}"
    msg = LXMF.LXMessage(destination, S.delivery_destination, text, title, desired_method=method)

    def _delivered(m):
        S.last_send_ts = time.time()
        S.last_send_state = "delivered"
        update_bridged_state(row_id, "delivered")

    def _failed(m):
        S.last_send_ts = time.time()
        S.last_send_state = "failed"
        update_bridged_state(row_id, "failed")

    msg.register_delivery_callback(_delivered)
    msg.register_failed_callback(_failed)
    S.router.handle_outbound(msg)
    S.outbound_count += 1
    update_bridged_state(row_id, "direct-sent" if method == LXMF.LXMessage.DIRECT else "propagated-sent")


def _downlink_topic_base() -> str | None:
    """Where to publish: explicit override, else learned from uplink traffic,
    else a best-effort region-less fallback (works on meshes that omit the
    region segment; self-corrects once real traffic is observed)."""
    if DOWNLINK_TOPIC_PREFIX:
        return DOWNLINK_TOPIC_PREFIX
    if S.downlink_topic_base:
        return S.downlink_topic_base
    return f"{MQTT_TOPIC_ROOT}/2/e/{DOWNLINK_CHANNEL}"


def send_meshtastic_text(text: str, sender_label: str = ""):
    """Build a Meshtastic TEXT packet from an inbound LXMF message, channel-
    encrypt it, and publish it to the downlink topic for a gateway to
    rebroadcast. Returns (state, topic)."""
    if not ENABLE_DOWNLINK:
        return "downlink-disabled", ""
    client = S.mqtt_client
    if client is None or not S.mqtt_connected:
        S.last_downlink_state = "mqtt-not-connected"
        return "mqtt-not-connected", ""
    if S.bridge_node_num is None:
        S.last_downlink_state = "rns-not-ready"
        return "rns-not-ready", ""

    # Compose "[sender] text" and clamp to the Meshtastic text payload cap
    # (trim on a char boundary so we never emit a partial multibyte tail).
    body = f"[{sender_label}] {text}" if sender_label else text
    b = body.encode("utf-8")
    if len(b) > DOWNLINK_MAX_BYTES:
        body = b[:DOWNLINK_MAX_BYTES].decode("utf-8", errors="ignore")

    data = mesh_pb2.Data()
    data.portnum = portnums_pb2.TEXT_MESSAGE_APP
    data.payload = body.encode("utf-8")

    packet = mesh_pb2.MeshPacket()
    packet.id = int.from_bytes(os.urandom(4), "little") or 1
    _pkt_set_from(packet, S.bridge_node_num)
    packet.to = 0xFFFFFFFF  # broadcast (v2 is channel-broadcast; DM mapping is future work)
    ch_hash = (DOWNLINK_CHANNEL_HASH if DOWNLINK_CHANNEL_HASH is not None
               else S.downlink_channel_hash if S.downlink_channel_hash is not None
               else channel_hash(DOWNLINK_CHANNEL, DOWNLINK_PSK))
    packet.channel = ch_hash
    packet.hop_limit = DOWNLINK_HOP_LIMIT
    packet.encrypted = encrypt_channel(packet.id, S.bridge_node_num, data.SerializeToString(), DOWNLINK_PSK)

    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.packet.CopyFrom(packet)
    envelope.channel_id = DOWNLINK_CHANNEL
    envelope.gateway_id = _node_hex(S.bridge_node_num)

    base = _downlink_topic_base()
    topic = f"{base}/{_node_hex(S.bridge_node_num)}"

    # Record the id BEFORE publishing so the re-uplinked echo can never race us
    # into re-forwarding it.
    S.injected_order.append(packet.id)
    try:
        client.publish(topic, envelope.SerializeToString(), qos=0)
    except Exception as e:
        S.last_downlink_state = f"publish-error: {e}"
        return S.last_downlink_state, topic

    S.downlink_count += 1
    S.last_downlink_ts = time.time()
    state = "sent" if (DOWNLINK_TOPIC_PREFIX or S.downlink_topic_base) else "sent-fallback-topic"
    S.last_downlink_state = state
    return state, topic


# --------------------------------------------------------------------------
# MQTT / Meshtastic decode
# --------------------------------------------------------------------------
def _node_hex(num: int) -> str:
    return f"!{num & 0xffffffff:08x}"


def _handle_data(node_id: str, data, topic: str):
    S.inbound_count += 1
    try:
        if data.portnum == portnums_pb2.TEXT_MESSAGE_APP:
            text = data.payload.decode("utf-8", errors="replace")
            record_mqtt(topic, "TEXT_MESSAGE_APP", True, text[:80])
            send_lxmf_text(node_id, text, topic)
        elif data.portnum == portnums_pb2.POSITION_APP:
            pos = mesh_pb2.Position()
            pos.ParseFromString(data.payload)
            lat = pos.latitude_i / 1e7 if pos.latitude_i else None
            lon = pos.longitude_i / 1e7 if pos.longitude_i else None
            if lat is not None and lon is not None:
                record_position(node_id, lat, lon, pos.altitude)
                record_mqtt(topic, "POSITION_APP", True, f"{lat:.5f},{lon:.5f}")
            else:
                record_mqtt(topic, "POSITION_APP", True, "no-fix")
        elif data.portnum == portnums_pb2.NODEINFO_APP:
            info = mesh_pb2.User()
            info.ParseFromString(data.payload)
            upsert_node(node_id, long_name=info.long_name or None, short_name=info.short_name or None)
            record_mqtt(topic, "NODEINFO_APP", True, info.long_name)
        else:
            record_mqtt(topic, portnums_pb2.PortNum.Name(data.portnum) if data.portnum in portnums_pb2.PortNum.values() else str(data.portnum), True, "")
    except Exception as e:
        record_mqtt(topic, "?", False, f"decode error: {e}")


def _learn_downlink(envelope, packet, topic: str):
    """Auto-learn the downlink topic prefix + channel hash from real uplink
    traffic on DOWNLINK_CHANNEL, so injection uses values the mesh has already
    proven it accepts (esp. the default channel's '' vs 'LongFast' name gotcha)."""
    try:
        if envelope.channel_id != DOWNLINK_CHANNEL:
            return
        if not DOWNLINK_TOPIC_PREFIX and "/" in topic:
            # strip the trailing "/<gateway-userid>" segment
            S.downlink_topic_base = topic.rsplit("/", 1)[0]
        if S.downlink_channel_hash is None:
            S.downlink_channel_hash = packet.channel & 0xFF
    except Exception:
        pass


def _process_envelope_bytes(payload: bytes, topic: str):
    """Shared by the real MQTT callback and the /api/test/synthetic endpoint --
    same decode path either way, so a synthetic-packet test genuinely exercises
    the same code real Meshtastic MQTT traffic would hit."""
    try:
        envelope = mqtt_pb2.ServiceEnvelope()
        envelope.ParseFromString(payload)
        packet = envelope.packet
        frm = _pkt_from(packet)
        node_id = _node_hex(frm)

        # Loop guard: drop the re-uplinked echo of anything we injected, or any
        # packet claiming to be from our own virtual node.
        if S.bridge_node_num is not None and (frm == S.bridge_node_num or packet.id in S.injected_order):
            record_mqtt(topic, "LOOP", False, "own downlink echo (ignored)")
            return

        _learn_downlink(envelope, packet, topic)

        if packet.HasField("decoded"):
            _handle_data(node_id, packet.decoded, topic)
        elif packet.encrypted:
            plain = decrypt_default_channel(packet)
            if plain is None:
                record_mqtt(topic, "?", False, "encrypted (non-default channel key)")
                return
            data = mesh_pb2.Data()
            try:
                data.ParseFromString(plain)
                _handle_data(node_id, data, topic)
            except Exception as e:
                record_mqtt(topic, "?", False, f"post-decrypt parse failed: {e}")
        else:
            record_mqtt(topic, "?", False, "no decoded/encrypted field")
    except Exception as e:
        # Not every message under the topic root is a ServiceEnvelope (e.g. a
        # /json/ subtree, if ever enabled) -- log and move on, never crash the
        # MQTT loop over one malformed/foreign payload.
        record_mqtt(topic, "?", False, f"envelope parse failed: {e}")


def _on_mqtt_message(client, userdata, msg):
    _process_envelope_bytes(msg.payload, msg.topic)


def _on_mqtt_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        S.mqtt_connected = True
        S.mqtt_error = None
        client.subscribe(f"{MQTT_TOPIC_ROOT}/#", qos=0)
        RNS.log(f"meshtastic-bridge: MQTT connected, subscribed {MQTT_TOPIC_ROOT}/#", RNS.LOG_NOTICE)
    else:
        S.mqtt_connected = False
        S.mqtt_error = f"connect rc={rc}"
        RNS.log(f"meshtastic-bridge: MQTT connect failed rc={rc}", RNS.LOG_ERROR)


def _on_mqtt_disconnect(client, userdata, disconnect_flags, reason_code, properties=None):
    # paho-mqtt v2 (CallbackAPIVersion.VERSION2) signature: 5 positional args.
    S.mqtt_connected = False
    if reason_code != 0:
        S.mqtt_error = f"disconnected rc={reason_code}"


def mqtt_thread():
    # Password precedence: inline MQTT_PASSWORD, else MQTT_PASSWORD_FILE, else none.
    # A blank MQTT_USERNAME connects anonymously (works with the bundled broker).
    password = MQTT_PASSWORD or None
    if not password and MQTT_PASSWORD_FILE:
        try:
            with open(MQTT_PASSWORD_FILE, "r") as f:
                password = f.read().strip()
        except Exception as e:
            S.mqtt_error = f"could not read MQTT_PASSWORD_FILE: {e}"
            RNS.log(f"meshtastic-bridge: {S.mqtt_error}", RNS.LOG_ERROR)

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id="meshtastic-reticulum-bridge")
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, password)
    client.on_connect = _on_mqtt_connect
    client.on_disconnect = _on_mqtt_disconnect
    client.on_message = _on_mqtt_message
    S.mqtt_client = client  # so the LXMF delivery callback can publish downlink

    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            client.loop_forever(retry_first_connection=True)
        except Exception as e:
            S.mqtt_connected = False
            S.mqtt_error = str(e)
            RNS.log(f"meshtastic-bridge: MQTT loop error: {e}, retrying in 10s", RNS.LOG_WARNING)
            time.sleep(10)


# --------------------------------------------------------------------------
# FastAPI status app
# --------------------------------------------------------------------------
app = FastAPI(title="meshtastic-reticulum-bridge")


@app.get("/healthz")
def healthz():
    ok = S.ready and S.mqtt_connected
    return {"status": "ok" if ok else "degraded", "rns_ready": S.ready, "mqtt_connected": S.mqtt_connected}


@app.get("/api/status")
def api_status():
    out = {
        "rns_ready": S.ready,
        "rns_error": S.error,
        "lxmf_address": S.lxmf_address,
        "target_lxmf_hash": TARGET_LXMF_HASH_ENV or None,
        "target_identity_known": bool(S.target_hash and RNS.Identity.recall(S.target_hash) is not None) if S.ready else None,
        "mqtt_connected": S.mqtt_connected,
        "mqtt_error": S.mqtt_error,
        "mqtt_topic": f"{MQTT_TOPIC_ROOT}/#",
        "inbound_count": S.inbound_count,
        "outbound_count": S.outbound_count,
        "last_send_ts": S.last_send_ts,
        "last_send_state": S.last_send_state,
        "downlink_enabled": ENABLE_DOWNLINK,
        "downlink_channel": DOWNLINK_CHANNEL,
        "downlink_topic": (_downlink_topic_base() + "/" + _node_hex(S.bridge_node_num)) if S.bridge_node_num is not None else None,
        "downlink_topic_learned": bool(S.downlink_topic_base),
        "downlink_channel_hash": S.downlink_channel_hash,
        "bridge_node_id": _node_hex(S.bridge_node_num) if S.bridge_node_num is not None else None,
        "downlink_count": S.downlink_count,
        "last_downlink_ts": S.last_downlink_ts,
        "last_downlink_state": S.last_downlink_state,
        "last_inbound_lxmf_ts": S.last_inbound_lxmf_ts,
        "uptime_s": round(time.time() - APP_START_TS),
    }
    if S.ready and S.reticulum is not None:
        try:
            stats = S.reticulum.get_interface_stats()
            out["interfaces"] = [
                {"name": i.get("name"), "status": bool(i.get("status"))}
                for i in stats.get("interfaces", [])
            ]
        except Exception:
            out["interfaces"] = []
    return JSONResponse(out)


@app.get("/api/nodes")
def api_nodes():
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM nodes ORDER BY last_seen DESC").fetchall()]


@app.get("/api/positions")
def api_positions(limit: int = 200):
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM positions ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]


@app.get("/api/messages")
def api_messages(limit: int = 100):
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM bridged_messages ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]


@app.get("/api/downlink")
def api_downlink(limit: int = 100):
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM downlink_messages ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]


@app.get("/api/mqtt_log")
def api_mqtt_log(limit: int = 100):
    with db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM mqtt_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]


class SyntheticPacket(BaseModel):
    text: str = "synthetic test packet from meshtastic-reticulum-bridge"
    from_node: int = 0xDEADBEEF
    encrypted: bool = True


@app.post("/api/test/synthetic")
def api_test_synthetic(pkt: SyntheticPacket):
    """Verification aid for when live Meshtastic MQTT traffic isn't available:
    builds a real ServiceEnvelope+MeshPacket+Data protobuf exactly as the
    Meshtastic MQTT integration would, optionally channel-encrypts it with the
    same default PSK a real default-channel packet would use, and feeds the
    resulting bytes through the identical decode path _on_mqtt_message uses --
    proving the protobuf decode, AES-CTR decrypt, and LXMF injection all work
    end-to-end without needing a live broker connection."""
    data = mesh_pb2.Data()
    data.portnum = portnums_pb2.TEXT_MESSAGE_APP
    data.payload = pkt.text.encode("utf-8")

    packet = mesh_pb2.MeshPacket()
    packet.id = int(time.time()) & 0xffffffff
    _pkt_set_from(packet, pkt.from_node)
    packet.to = 0xFFFFFFFF  # broadcast

    if pkt.encrypted:
        packet.encrypted = encrypt_channel(packet.id, pkt.from_node, data.SerializeToString(), DEFAULT_PSK)
    else:
        packet.decoded.CopyFrom(data)

    envelope = mqtt_pb2.ServiceEnvelope()
    envelope.packet.CopyFrom(packet)
    envelope.channel_id = "LongFast"
    envelope.gateway_id = _node_hex(pkt.from_node)

    before = (S.inbound_count, S.outbound_count)
    _process_envelope_bytes(envelope.SerializeToString(), "synthetic/test")
    return {
        "ok": True,
        "node_id": _node_hex(pkt.from_node),
        "inbound_count_before": before[0],
        "inbound_count_after": S.inbound_count,
        "outbound_count_before": before[1],
        "outbound_count_after": S.outbound_count,
        "note": "check /api/messages and /api/mqtt_log for the resulting rows",
    }


class DownlinkTest(BaseModel):
    text: str = "synthetic downlink test from meshtastic-reticulum-bridge"
    sender: str = "test"


@app.post("/api/test/downlink")
def api_test_downlink(req: DownlinkTest):
    """Exercise the Reticulum->Meshtastic path without a live LXMF sender:
    builds and publishes a real downlink ServiceEnvelope through the exact same
    encrypt-and-publish code an inbound LXMF message would drive. Requires MQTT
    connected (the bundled broker is fine); a gateway with Downlink enabled on
    the channel then rebroadcasts it onto LoRa."""
    before = S.downlink_count
    state, topic = send_meshtastic_text(req.text, sender_label=req.sender)
    record_downlink("synthetic-test", req.sender, req.text, state, topic)
    return {
        "ok": state.startswith("sent"),
        "state": state,
        "topic": topic,
        "downlink_count_before": before,
        "downlink_count_after": S.downlink_count,
        "note": "check /api/downlink; a gateway with Downlink enabled rebroadcasts it to LoRa",
    }


def _run_uvicorn():
    import uvicorn
    config = uvicorn.Config(app, host="0.0.0.0", port=LISTEN_PORT, log_level="info")
    uvicorn.Server(config).run()


if __name__ == "__main__":
    threading.Thread(target=_run_uvicorn, daemon=True, name="uvicorn").start()
    threading.Thread(target=mqtt_thread, daemon=True, name="mqtt").start()
    init_rns()  # main thread: required for RNS's internal signal.signal() calls
