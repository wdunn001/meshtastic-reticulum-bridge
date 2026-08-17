"""meshtastic-reticulum-bridge -- one-way (v1) Meshtastic -> Reticulum/LXMF bridge.

Subscribes (read-only) to a Meshtastic MQTT feed, decodes the standard Meshtastic
protobufs (ServiceEnvelope), forwards TEXT_MESSAGE_APP packets into Reticulum as
LXMF messages delivered to a configured destination, and records POSITION_APP /
NODEINFO_APP packets to local SQLite (for a future unified map). It reads from
MQTT, so it never grabs the node's serial port -- it can run alongside any other
tool (e.g. an ATAK/OpenTAKServer gateway) that already owns the serial.

RNS/LXMF side runs a STANDALONE RNS instance (its own config dir + identity) and
joins the network purely over its own interfaces (config/rns-config): by default
a LAN AutoInterface (IPv6 link-local multicast) so it peers with any local
Reticulum node, plus an optional TCP backstop. It deliberately does NOT ride an
rnsd "shared instance" RPC socket -- that path silently drops inbound LXMF for a
process with a genuinely separate identity/config dir, so standalone mode
sidesteps the whole class of bug.

Config is entirely via environment variables (see the compose file / .env):
TARGET_LXMF_HASH (required destination), optional PROPAGATION_NODE_HASH, and the
MQTT_* settings. The bundled docker-compose ships a Mosquitto broker so you can
point a Meshtastic node's MQTT uplink straight at it.

RNS.Reticulum() must run on the process's main thread (installs signal
handlers). Same pattern as comms-web: uvicorn runs in a background thread,
RNS/MQTT init + the MQTT loop drive the main thread.
"""
import json
import os
import sqlite3
import struct
import threading
import time
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


def _pkt_from(packet) -> int:
    # MeshPacket's proto field is literally named "from" -- a reserved Python
    # keyword, so protoc does NOT expose it as `.from_` (confirmed live: that
    # raises AttributeError). Must go through getattr/setattr on the literal
    # name instead.
    return getattr(packet, "from")


def _pkt_set_from(packet, value: int):
    setattr(packet, "from", value)


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
    inbound_count = 0
    outbound_count = 0


S = RNSState()


def _on_lxmf_delivery(message):
    """Inbound LXMF -> Meshtastic downlink is deliberately NOT implemented in
    v1 (see README "Bidirectional" section) -- OTS_MESHTASTIC_DOWNLINK_CHANNELS
    is empty on the live node, meaning downlink is already intentionally
    disabled upstream of anything this bridge could do. This handler just logs
    that a message arrived at the bridge's own delivery destination."""
    try:
        RNS.log(f"meshtastic-bridge: received inbound LXMF from "
                f"{RNS.hexrep(message.source_hash, delimit=False)} (not relayed to mesh -- v1 is uplink-only)",
                RNS.LOG_NOTICE)
    except Exception:
        pass


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
    RNS.log(f"meshtastic-bridge: ready, LXMF address {S.lxmf_address}", RNS.LOG_NOTICE)

    while True:
        time.sleep(SYNC_INTERVAL_S)
        if S.target_hash and RNS.Identity.recall(S.target_hash) is None:
            RNS.Transport.request_path(S.target_hash)


def send_lxmf_text(node_id: str, text: str, topic: str):
    """Forward one Meshtastic text message into Reticulum as an LXMF message
    to the pinned TARGET_LXMF_HASH (comms.quasarke.net's delivery destination
    by default). Same direct-vs-propagated fallback logic as
    reticulum-web-stack's /send: direct if the recipient's identity is known
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


def _process_envelope_bytes(payload: bytes, topic: str):
    """Shared by the real MQTT callback and the /api/test/synthetic endpoint --
    same decode path either way, so a synthetic-packet test genuinely exercises
    the same code real Meshtastic MQTT traffic would hit."""
    try:
        envelope = mqtt_pb2.ServiceEnvelope()
        envelope.ParseFromString(payload)
        packet = envelope.packet
        node_id = _node_hex(_pkt_from(packet))
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
    """Verification aid for when live Meshtastic MQTT traffic isn't available
    (e.g. the broker credential gap documented in README.md): builds a real
    ServiceEnvelope+MeshPacket+Data protobuf exactly as the Meshtastic MQTT
    integration would, optionally channel-encrypts it with the same default
    PSK a real default-channel packet would use, and feeds the resulting bytes
    through the identical decode path _on_mqtt_message uses -- proving the
    protobuf decode, AES-CTR decrypt, and LXMF injection all work end-to-end
    without needing a live broker connection."""
    data = mesh_pb2.Data()
    data.portnum = portnums_pb2.TEXT_MESSAGE_APP
    data.payload = pkt.text.encode("utf-8")

    packet = mesh_pb2.MeshPacket()
    packet.id = int(time.time()) & 0xffffffff
    _pkt_set_from(packet, pkt.from_node)
    packet.to = 0xFFFFFFFF  # broadcast

    if pkt.encrypted:
        nonce = struct.pack("<II", packet.id, _pkt_from(packet)) + b"\x00" * 8
        cipher = Cipher(algorithms.AES(DEFAULT_PSK), modes.CTR(nonce))
        enc = cipher.encryptor()
        packet.encrypted = enc.update(data.SerializeToString()) + enc.finalize()
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


def _run_uvicorn():
    import uvicorn
    config = uvicorn.Config(app, host="0.0.0.0", port=LISTEN_PORT, log_level="info")
    uvicorn.Server(config).run()


if __name__ == "__main__":
    threading.Thread(target=_run_uvicorn, daemon=True, name="uvicorn").start()
    threading.Thread(target=mqtt_thread, daemon=True, name="mqtt").start()
    init_rns()  # main thread: required for RNS's internal signal.signal() calls
