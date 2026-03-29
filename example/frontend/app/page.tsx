"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { UserManager, WebStorageStateStore } from "oidc-client-ts";
import {
  connect,
  jwtAuthenticator,
  NatsConnection,
  StringCodec,
} from "nats.ws";
import { createUser } from "nkeys.js";

// ---------------------------------------------------------------------------
// Config — matches docker-local setup
// ---------------------------------------------------------------------------
const KEYCLOAK_URL = "http://localhost:9090/realms/chatapp";
const CLIENT_ID = "nats-chat";
const AUTH_SERVICE_URL = "http://localhost:8080";
const NATS_WS_URL = "ws://localhost:9222";
const ROOM = "room.general";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface UserInfo {
  sub: string;
  email: string;
  name: string;
  preferred_username: string;
  given_name: string;
  family_name: string;
}

interface AuthResponse {
  nats_jwt: string;
  user: UserInfo;
}

// ---------------------------------------------------------------------------
// OIDC setup (Keycloak via oidc-client-ts)
// ---------------------------------------------------------------------------
function createUserManager() {
  return new UserManager({
    authority: KEYCLOAK_URL,
    client_id: CLIENT_ID,
    redirect_uri: window.location.origin + "/",
    post_logout_redirect_uri: window.location.origin + "/",
    response_type: "code",
    scope: "openid profile email",
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    automaticSilentRenew: false,
  });
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function Home() {
  const [status, setStatus] = useState("Initializing...");
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const [input, setInput] = useState("");
  const [natsConn, setNatsConn] = useState<NatsConnection | null>(null);

  const umRef = useRef<UserManager | null>(null);
  const scRef = useRef(StringCodec());

  // -- 1. Handle OIDC callback / check session --
  useEffect(() => {
    const um = createUserManager();
    umRef.current = um;

    (async () => {
      // Check if this is an OIDC callback (has ?code= in URL)
      if (window.location.search.includes("code=")) {
        try {
          setStatus("Processing login callback...");
          const oidcUser = await um.signinRedirectCallback();
          // Clean URL
          window.history.replaceState({}, "", "/");
          if (!oidcUser.id_token)
            throw new Error("No id_token in OIDC response");
          await doConnectToNats(oidcUser.id_token);
        } catch (err) {
          setStatus(`Callback error: ${err}`);
        }
        return;
      }

      // Check for existing session
      const oidcUser = await um.getUser();
      if (oidcUser && !oidcUser.expired && oidcUser.id_token) {
        await doConnectToNats(oidcUser.id_token);
      } else {
        setStatus("Not logged in.");
      }
    })();

    return () => {
      um.clearStaleState();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // -- 2. Get NATS JWT from auth service, connect to NATS --
  const doConnectToNats = useCallback(async (idToken: string) => {
    try {
      setStatus("Generating NATS keypair...");

      // Generate ephemeral Ed25519 keypair — private key stays in browser RAM
      const nkeyUser = createUser();
      const seed = nkeyUser.getSeed();
      const publicKey = nkeyUser.getPublicKey();

      setStatus("Getting NATS JWT from auth service...");

      // Call our auth service: SSO token + public key → NATS JWT + user info
      const res = await fetch(`${AUTH_SERVICE_URL}/auth`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sso_token: idToken,
          nats_public_key: publicKey,
        }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({ message: res.statusText }));
        const msg = body?.message || res.statusText;
        if (res.status === 401) {
          // Token expired or invalid — clear session and prompt re-login
          setStatus(`Session expired: ${msg}`);
          setUserInfo(null);
          await umRef.current?.removeUser();
          return;
        }
        throw new Error(`Auth service ${res.status}: ${msg}`);
      }

      const data: AuthResponse = await res.json();

      setUserInfo(data.user);
      setStatus("Connecting to NATS via WebSocket...");

      // Connect to NATS via WebSocket with JWT auth
      const nc = await connect({
        servers: NATS_WS_URL,
        authenticator: jwtAuthenticator(data.nats_jwt, seed),
      });

      setNatsConn(nc);
      setStatus(`Connected to NATS! Subscribed to ${ROOM}`);

      // Subscribe to the room
      const sub = nc.subscribe(ROOM);
      (async () => {
        for await (const msg of sub) {
          const text = scRef.current.decode(msg.data);
          setMessages((prev) => [...prev.slice(-99), text]);
        }
      })();

      // Handle disconnect
      nc.closed().then(() => {
        setStatus("Disconnected from NATS.");
        setNatsConn(null);
      });
    } catch (err) {
      setStatus(`Error: ${err}`);
      console.error(err);
    }
  }, []);

  // -- 3. Actions --
  const handleLogin = () => {
    umRef.current?.signinRedirect();
  };

  const handleLogout = async () => {
    natsConn?.close();
    setNatsConn(null);
    setMessages([]);
    setUserInfo(null);
    await umRef.current?.signoutRedirect();
  };

  const handleSend = () => {
    if (!natsConn || !input.trim() || !userInfo) return;
    const displayName = userInfo.name || userInfo.preferred_username;
    const text = `[${displayName}] ${input.trim()}`;
    natsConn.publish(ROOM, scRef.current.encode(text));
    setInput("");
  };

  // -- Render --
  return (
    <div style={{ maxWidth: 600 }}>
      <h1>NATS Chat Demo</h1>
      <p style={{ color: "#666", fontSize: 14 }}>
        Keycloak OIDC &rarr; Auth Service (NATS JWT) &rarr; NATS WebSocket
      </p>

      <div
        style={{
          padding: "8px 12px",
          background: natsConn ? "#e6ffe6" : "#fff3e6",
          borderRadius: 6,
          marginBottom: 16,
          fontSize: 14,
        }}
      >
        {status}
      </div>

      {!userInfo && (
        <button onClick={handleLogin} style={btnStyle}>
          Login with Keycloak
        </button>
      )}

      {userInfo && (
        <>
          <div
            style={{
              padding: 12,
              background: "#f0f4ff",
              borderRadius: 6,
              marginBottom: 12,
              fontSize: 14,
            }}
          >
            <strong>{userInfo.name}</strong>{" "}
            <span style={{ color: "#666" }}>(@{userInfo.preferred_username})</span>
            <br />
            <span style={{ fontSize: 12, color: "#888" }}>{userInfo.email}</span>
            <button
              onClick={handleLogout}
              style={{
                ...btnStyle,
                background: "#eee",
                color: "#333",
                float: "right",
                marginTop: -4,
              }}
            >
              Logout
            </button>
          </div>

          <div
            style={{
              border: "1px solid #ddd",
              borderRadius: 6,
              padding: 12,
              height: 300,
              overflowY: "auto",
              marginBottom: 8,
              background: "#fafafa",
              fontFamily: "monospace",
              fontSize: 13,
            }}
          >
            {messages.length === 0 && (
              <span style={{ color: "#999" }}>
                No messages yet. Open another browser tab and send one!
              </span>
            )}
            {messages.map((msg, i) => (
              <div key={i}>{msg}</div>
            ))}
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSend()}
              placeholder={`Message ${ROOM}...`}
              style={{
                flex: 1,
                padding: "8px 12px",
                borderRadius: 6,
                border: "1px solid #ddd",
                fontSize: 14,
              }}
            />
            <button onClick={handleSend} style={btnStyle} disabled={!natsConn}>
              Send
            </button>
          </div>
        </>
      )}
    </div>
  );
}

const btnStyle: React.CSSProperties = {
  padding: "8px 16px",
  borderRadius: 6,
  border: "none",
  background: "#0070f3",
  color: "white",
  cursor: "pointer",
  fontSize: 14,
};
