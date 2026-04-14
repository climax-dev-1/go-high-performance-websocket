// WS Relay demo client.
// Generates an Ed25519 keypair via WebCrypto, derives its did:key, fetches a
// UCAN bundle from the relay, completes the challenge-response handshake, and
// exposes a small pub/sub UI.
//
// The browser treats delegation tokens as opaque base64 blobs — it never parses
// DAG-CBOR.

(() => {
  const $ = (id) => document.getElementById(id);
  const statusDot = $("status-dot");
  const statusText = $("status-text");
  const log = $("handshake-log");

  function setStatus(state, text) {
    statusDot.className = "dot dot-" + state;
    statusText.textContent = text;
  }

  function logLine(kind, msg) {
    const span = document.createElement("span");
    span.className = kind;
    span.textContent = msg + "\n";
    log.appendChild(span);
    log.scrollTop = log.scrollHeight;
  }

  // --- base58btc (Bitcoin alphabet) via BigInt ---
  const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  function base58btcEncode(bytes) {
    // Handle leading zero bytes as leading "1"s.
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    let out = "";
    while (n > 0n) {
      const r = Number(n % 58n);
      n = n / 58n;
      out = B58_ALPHABET[r] + out;
    }
    return "1".repeat(zeros) + out;
  }

  function bytesToB64Url(bytes) {
    let s = btoa(String.fromCharCode(...bytes));
    return s.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }

  function b64UrlToBytes(s) {
    s = s.replaceAll("-", "+").replaceAll("_", "/");
    while (s.length % 4 !== 0) s += "=";
    const raw = atob(s);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  // --- state ---
  let clientKeyPair = null;
  let clientDID = null;
  let relayDID = null;
  let subjectPrefix = "demo.";
  let pubUcan = null;
  let subUcan = null;
  let ws = null;
  const activeSubs = new Set();
  let connected = false;

  const CHAT_PREFIX = "demo.chat.";
  let currentRoom = "lobby";
  let currentChatSubject = CHAT_PREFIX + currentRoom;
  let myNick = "anon-" + Math.random().toString(36).slice(2, 6);

  // --- identity bootstrap ---
  async function generateIdentity() {
    if (!window.crypto?.subtle?.generateKey) {
      $("browser-warning").classList.remove("hidden");
      throw new Error("WebCrypto unavailable");
    }
    try {
      clientKeyPair = await crypto.subtle.generateKey(
        { name: "Ed25519" },
        true,
        ["sign", "verify"],
      );
    } catch (e) {
      $("browser-warning").classList.remove("hidden");
      throw e;
    }
    const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", clientKeyPair.publicKey));
    // multicodec: 0xed 0x01 + 32 raw bytes
    const prefixed = new Uint8Array(2 + rawPub.length);
    prefixed[0] = 0xed;
    prefixed[1] = 0x01;
    prefixed.set(rawPub, 2);
    clientDID = "did:key:z" + base58btcEncode(prefixed);
    $("client-did").textContent = clientDID;
    logLine("ok", "generated client " + clientDID);
  }

  async function fetchRelayInfo() {
    const r = await fetch("/relay-info");
    const info = await r.json();
    relayDID = info.relayDid;
    subjectPrefix = info.subjectPrefix || "demo.";
    $("relay-did").textContent = relayDID;
    $("subject-prefix").textContent = subjectPrefix + "*";
    logLine("info", "relay " + relayDID);
  }

  async function fetchUCAN() {
    const r = await fetch("/issue-ucan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientDid: clientDID }),
    });
    if (!r.ok) {
      throw new Error("issue-ucan failed: " + r.status);
    }
    const body = await r.json();
    pubUcan = body.pubDelegation;
    subUcan = body.subDelegation;
    logLine("ok", "received publish + subscribe delegations");
    renderCaps(["pub: /nats/publish " + subjectPrefix + "*", "sub: /nats/subscribe " + subjectPrefix + "*"]);
  }

  function renderCaps(caps) {
    const el = $("caps");
    el.innerHTML = "";
    for (const c of caps) {
      const span = document.createElement("span");
      span.className = "cap";
      span.textContent = c;
      el.appendChild(span);
    }
  }

  // --- WS lifecycle ---
  async function connect() {
    if (ws) {
      ws.close();
      ws = null;
    }
    if (!clientKeyPair || !pubUcan || !subUcan) {
      logLine("err", "identity not ready");
      return;
    }
    setStatus("connecting", "connecting…");
    const url = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws";
    ws = new WebSocket(url);
    ws.onopen = () => logLine("info", "ws open, awaiting challenge");
    ws.onclose = (ev) => {
      connected = false;
      setStatus("off", "disconnected (" + ev.code + ")");
      logLine("info", "ws closed " + ev.code + " " + (ev.reason || ""));
    };
    ws.onerror = () => setStatus("error", "error");
    ws.onmessage = (ev) => handleMessage(ev.data);
  }

  async function handleMessage(raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { logLine("err", "bad json from server"); return; }
    switch (msg.type) {
      case "challenge": return onChallenge(msg);
      case "ready":     return onReady(msg);
      case "error":     return onError(msg);
      case "ack":       return onAck(msg);
      case "event":     return onEvent(msg);
      default:          logLine("info", "unknown: " + msg.type);
    }
  }

  async function onChallenge(msg) {
    logLine("info", "challenge nonce " + msg.nonce.slice(0, 16) + "…");
    const nonceBytes = b64UrlToBytes(msg.nonce);
    const sig = new Uint8Array(await crypto.subtle.sign(
      { name: "Ed25519" },
      clientKeyPair.privateKey,
      nonceBytes,
    ));
    ws.send(JSON.stringify({
      type: "auth",
      clientDid: clientDID,
      signature: bytesToB64Url(sig),
      pubUcan: pubUcan,
      subUcan: subUcan,
    }));
    logLine("ok", "sent auth");
  }

  function onReady(msg) {
    connected = true;
    $("conn-id").textContent = msg.connId;
    setStatus("ready", "ready");
    logLine("ok", "authenticated as " + msg.clientDid.slice(0, 20) + "…");
    enableChat();
    subscribeChat(currentChatSubject);
    appendSystemChat("joined " + currentChatSubject + " as " + myNick);
  }

  function onError(msg) {
    setStatus("error", msg.code);
    logLine("err", "error [" + msg.code + "] " + msg.message);
  }

  function onAck(msg) {
    logLine("ok", "ack " + msg.op + " " + msg.subject);
    if (msg.op === "subscribe") {
      activeSubs.add(msg.subject);
      renderSubs();
    } else if (msg.op === "unsubscribe") {
      activeSubs.delete(msg.subject);
      renderSubs();
    }
  }

  function onEvent(msg) {
    // Chat frames route to the chat log instead of the raw feed.
    if (msg.subject.startsWith(CHAT_PREFIX) && isChatPayload(msg.payload)) {
      appendChatMessage(msg.subject, msg.payload, msg.receivedAt);
      return;
    }
    const feed = $("feed");
    const div = document.createElement("div");
    div.className = "event";
    const received = new Date(Math.floor(msg.receivedAt / 1e6)).toLocaleTimeString();
    const payloadStr = typeof msg.payload === "string" ? msg.payload : JSON.stringify(msg.payload);
    div.innerHTML = `<span class="subj"></span><span class="time"></span><div class="payload"></div>`;
    div.querySelector(".subj").textContent = msg.subject;
    div.querySelector(".time").textContent = received;
    div.querySelector(".payload").textContent = payloadStr;
    feed.prepend(div);
    while (feed.childElementCount > 100) feed.removeChild(feed.lastChild);
  }

  function isChatPayload(p) {
    return p && typeof p === "object" && typeof p.text === "string" && typeof p.nick === "string";
  }

  function appendChatMessage(subject, payload, receivedAt) {
    if (subject !== currentChatSubject) return; // only render the active room
    const log = $("chat-log");
    const div = document.createElement("div");
    const mine = payload.from && payload.from === clientDID;
    div.className = "chat-msg" + (mine ? " mine" : "");
    const time = new Date(Math.floor(receivedAt / 1e6)).toLocaleTimeString();
    const meta = document.createElement("div");
    meta.className = "meta";
    const nickEl = document.createElement("span");
    nickEl.className = "nick";
    nickEl.textContent = payload.nick;
    const timeEl = document.createElement("span");
    timeEl.className = "time";
    timeEl.textContent = time;
    meta.appendChild(nickEl);
    meta.appendChild(timeEl);
    const text = document.createElement("div");
    text.className = "text";
    text.textContent = payload.text;
    div.appendChild(meta);
    div.appendChild(text);
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    while (log.childElementCount > 200) log.removeChild(log.firstChild);
  }

  function appendSystemChat(text) {
    const log = $("chat-log");
    const div = document.createElement("div");
    div.className = "chat-msg system";
    div.textContent = "— " + text + " —";
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  function enableChat() {
    $("chat-input").disabled = false;
    const btn = $("chat-form").querySelector("button");
    if (btn) btn.disabled = false;
  }

  function subscribeChat(subject) {
    if (!connected) return;
    ws.send(JSON.stringify({ type: "subscribe", subject }));
    activeSubs.add(subject);
    renderSubs();
  }

  function switchRoom(newRoom) {
    const next = CHAT_PREFIX + newRoom.trim();
    if (next === currentChatSubject) return;
    if (connected && activeSubs.has(currentChatSubject)) {
      ws.send(JSON.stringify({ type: "unsubscribe", subject: currentChatSubject }));
      activeSubs.delete(currentChatSubject);
    }
    $("chat-log").innerHTML = "";
    currentRoom = newRoom.trim();
    currentChatSubject = next;
    appendSystemChat("switching to " + currentChatSubject);
    if (connected) subscribeChat(currentChatSubject);
  }

  function sendChat(text) {
    if (!connected || !text.trim()) return;
    const payload = {
      nick: ($("chat-nick").value.trim() || myNick),
      text: text,
      from: clientDID,
      ts: Date.now(),
    };
    ws.send(JSON.stringify({
      type: "publish",
      subject: currentChatSubject,
      payload,
    }));
  }

  function renderSubs() {
    const ul = $("subs-list");
    ul.innerHTML = "";
    for (const s of activeSubs) {
      const li = document.createElement("li");
      const code = document.createElement("code");
      code.textContent = s;
      const btn = document.createElement("button");
      btn.textContent = "unsubscribe";
      btn.onclick = () => sendUnsubscribe(s);
      li.appendChild(code);
      li.appendChild(btn);
      ul.appendChild(li);
    }
  }

  function sendSubscribe(subject) {
    if (!connected) { logLine("err", "not connected"); return; }
    ws.send(JSON.stringify({ type: "subscribe", subject }));
  }
  function sendUnsubscribe(subject) {
    if (!connected) return;
    ws.send(JSON.stringify({ type: "unsubscribe", subject }));
  }
  function sendPublish(subject, payloadRaw) {
    if (!connected) { logLine("err", "not connected"); return; }
    let payload;
    try { payload = JSON.parse(payloadRaw); }
    catch (e) { logLine("err", "payload must be valid JSON"); return; }
    ws.send(JSON.stringify({ type: "publish", subject, payload }));
  }

  // --- UI wiring ---
  $("sub-form").addEventListener("submit", (e) => {
    e.preventDefault();
    sendSubscribe($("sub-subject").value.trim());
  });
  $("pub-form").addEventListener("submit", (e) => {
    e.preventDefault();
    sendPublish($("pub-subject").value.trim(), $("pub-payload").value);
  });
  $("connect-btn").addEventListener("click", () => connect());

  $("chat-nick").value = myNick;
  $("chat-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const input = $("chat-input");
    sendChat(input.value);
    input.value = "";
  });
  $("chat-room").addEventListener("change", (e) => {
    switchRoom(e.target.value);
  });

  // --- boot ---
  (async () => {
    setStatus("connecting", "preparing…");
    try {
      await fetchRelayInfo();
      await generateIdentity();
      await fetchUCAN();
      await connect();
    } catch (e) {
      setStatus("error", "init failed");
      logLine("err", String(e));
    }
  })();
})();
