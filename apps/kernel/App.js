/**
 * Sacred Gatekeeper — Phone App (Kernel)
 *
 * Device flow:
 *   1. Generate a local Ed25519 keypair + stable device id.
 *   2. Register with the broker using a short-lived pairing code.
 *   3. Upload Expo push token so the broker can notify the device.
 *   4. Poll the local broker on-LAN, or Supabase off-LAN if configured.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Animated, FlatList, Platform, StatusBar, StyleSheet,
  Text, TouchableOpacity, View, Alert, ActivityIndicator, TextInput,
} from 'react-native';
import * as LocalAuthentication from 'expo-local-authentication';
import * as SecureStore from 'expo-secure-store';
import * as Notifications from 'expo-notifications';
import nacl from 'tweetnacl';

// ── Config ────────────────────────────────────────────────────────────────────

const BROKER_HTTP = process.env.EXPO_PUBLIC_BROKER_HTTP ?? 'http://127.0.0.1:9998';
const EXPO_PROJECT_ID = process.env.EXPO_PUBLIC_EXPO_PROJECT_ID ?? '';
const SUPABASE_URL = (process.env.EXPO_PUBLIC_SUPABASE_URL ?? '').replace(/\/$/, '');
const SUPABASE_ANON_KEY = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY ?? '';
const POLL_MS     = 2_000;
const REMOTE_ENABLED = Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);

// ── Notification handler ──────────────────────────────────────────────────────

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge:  true,
  }),
});

// ── Risk colour palette ───────────────────────────────────────────────────────

const RISK_COLOR = {
  LOW:      '#27c93f',
  MEDIUM:   '#f0c040',
  HIGH:     '#ff6b35',
  CRITICAL: '#e83e5a',
};

const riskColor = (r) => RISK_COLOR[(r ?? '').toUpperCase()] ?? '#aaa';

// ── API helpers ───────────────────────────────────────────────────────────────

async function fetchPending() {
  const r = await fetch(`${BROKER_HTTP}/pending`, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function postApprove(id, signature) {
  const r = await fetch(`${BROKER_HTTP}/approve/${id}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ signature }),
  });
  return r.json();
}

async function postDeny(id) {
  const r = await fetch(`${BROKER_HTTP}/deny/${id}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    '{}',
  });
  return r.json();
}

async function fetchDevices() {
  const r = await fetch(`${BROKER_HTTP}/devices`, { cache: 'no-store' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function registerDevice(payload) {
  const r = await fetch(`${BROKER_HTTP}/devices/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return r.json();
}

async function refreshDevice(payload) {
  const r = await fetch(`${BROKER_HTTP}/devices/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return r.json();
}

async function revokeDevice(deviceId) {
  const r = await fetch(`${BROKER_HTTP}/devices/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id: deviceId }),
  });
  return r.json();
}

function supabaseHeaders() {
  return {
    'Content-Type': 'application/json',
    apikey: SUPABASE_ANON_KEY,
    Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
  };
}

async function fetchRemotePending(deviceId) {
  const url = `${SUPABASE_URL}/rest/v1/sg_notifications?device_id=eq.${encodeURIComponent(deviceId)}&resolved_at=is.null&select=request_id,summary,risk,created_at&order=created_at.desc`;
  const r = await fetch(url, {
    headers: supabaseHeaders(),
    cache: 'no-store',
  });
  if (!r.ok) throw new Error(`Supabase HTTP ${r.status}`);
  const rows = await r.json();
  return rows.map((row) => ({
    id: row.request_id,
    summary: row.summary,
    risk: row.risk,
    created_at: row.created_at,
    source: 'remote',
  }));
}

async function submitRemoteDecision({ deviceId, requestId, action, signature }) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/sg_decisions`, {
    method: 'POST',
    headers: {
      ...supabaseHeaders(),
      Prefer: 'return=minimal',
    },
    body: JSON.stringify({
      request_id: requestId,
      device_id: deviceId,
      action,
      signature,
    }),
  });
  return { ok: r.ok, status: r.status };
}

// ── Key management ────────────────────────────────────────────────────────────

function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

function utf8ToBytes(value) {
  return new TextEncoder().encode(value);
}

function randomId(prefix) {
  return `${prefix}_${bytesToHex(nacl.randomBytes(8))}`;
}

async function loadOrCreateKeyPair() {
  let raw = await SecureStore.getItemAsync('sg_private_key');
  if (raw) {
    return nacl.sign.keyPair.fromSecretKey(hexToBytes(raw));
  }
  const kp = nacl.sign.keyPair();
  await SecureStore.setItemAsync('sg_private_key', bytesToHex(kp.secretKey));
  return kp;
}

async function loadOrCreateDeviceId() {
  const existing = await SecureStore.getItemAsync('sg_device_id');
  if (existing) return existing;
  const created = randomId('kernel');
  await SecureStore.setItemAsync('sg_device_id', created);
  return created;
}

function signRid(kp, rid) {
  const sig = nacl.sign.detached(utf8ToBytes(rid), kp.secretKey);
  return bytesToHex(sig);
}

function encodePublicKey(kp) {
  return bytesToHex(kp.publicKey);
}

async function getPushToken() {
  try {
    const permissions = await Notifications.requestPermissionsAsync();
    if (permissions.status !== 'granted' || !EXPO_PROJECT_ID) {
      return null;
    }
    const response = await Notifications.getExpoPushTokenAsync({ projectId: EXPO_PROJECT_ID });
    return response.data;
  } catch {
    return null;
  }
}

// ── Pulse animation ───────────────────────────────────────────────────────────

function usePulse(condition) {
  const scale   = useRef(new Animated.Value(1)).current;
  const opacity = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    if (!condition) {
      scale.setValue(1);
      opacity.setValue(1);
      return;
    }
    const loop = Animated.loop(
      Animated.sequence([
        Animated.parallel([
          Animated.timing(scale,   { toValue: 1.04, duration: 700, useNativeDriver: true }),
          Animated.timing(opacity, { toValue: 0.80, duration: 700, useNativeDriver: true }),
        ]),
        Animated.parallel([
          Animated.timing(scale,   { toValue: 1,    duration: 700, useNativeDriver: true }),
          Animated.timing(opacity, { toValue: 1,    duration: 700, useNativeDriver: true }),
        ]),
      ])
    );
    loop.start();
    return () => loop.stop();
  }, [condition, scale, opacity]);

  return { scale, opacity };
}

// ── RequestCard ───────────────────────────────────────────────────────────────

function RequestCard({ item, onApprove, onDeny, busy }) {
  const { scale, opacity } = usePulse(true);
  const color = riskColor(item.risk);

  return (
    <Animated.View style={[styles.card, { borderColor: color, transform: [{ scale }], opacity }]}>
      <View style={[styles.riskBadge, { backgroundColor: color }]}>
        <Text style={styles.riskText}>{(item.risk ?? 'UNKNOWN').toUpperCase()}</Text>
      </View>
      <Text style={styles.summary}>{item.summary ?? '(no summary)'}</Text>
      <Text style={styles.rid}>ID: {item.id.slice(0, 12)}…</Text>
      <View style={styles.btnRow}>
        <TouchableOpacity
          style={[styles.btn, styles.btnApprove, busy && styles.btnDisabled]}
          onPress={() => onApprove(item)}
          disabled={busy}
        >
          <Text style={styles.btnText}>✓ Approve</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.btn, styles.btnDeny, busy && styles.btnDisabled]}
          onPress={() => onDeny(item)}
          disabled={busy}
        >
          <Text style={styles.btnText}>✗ Deny</Text>
        </TouchableOpacity>
      </View>
    </Animated.View>
  );
}

// ── HistoryItem ───────────────────────────────────────────────────────────────

function HistoryItem({ item }) {
  const color  = item.decision === 'approve' ? '#27c93f' : '#e83e5a';
  const symbol = item.decision === 'approve' ? '✓' : '✗';
  return (
    <View style={styles.histRow}>
      <Text style={[styles.histSymbol, { color }]}>{symbol}</Text>
      <Text style={styles.histText} numberOfLines={1}>{item.summary}</Text>
      <Text style={[styles.histRisk, { color: riskColor(item.risk) }]}>{item.risk}</Text>
    </View>
  );
}

function DeviceItem({ item, currentDeviceId, onRevoke, busy }) {
  const isCurrent = item.device_id === currentDeviceId;
  return (
    <View style={styles.deviceRow}>
      <View style={styles.deviceRowMain}>
        <Text style={styles.deviceName}>
          {item.device_name} {isCurrent ? '(this device)' : ''}
        </Text>
        <Text style={styles.deviceMeta}>
          {item.platform || 'unknown'} • push {item.push_enabled ? 'enabled' : 'not enabled'} • {item.active ? 'active' : 'revoked'}
        </Text>
      </View>
      {item.active ? (
        <TouchableOpacity
          style={[styles.smallButton, busy && styles.btnDisabled]}
          disabled={busy}
          onPress={() => onRevoke(item)}
        >
          <Text style={styles.smallButtonText}>Revoke</Text>
        </TouchableOpacity>
      ) : null}
    </View>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [queue,     setQueue   ] = useState([]);
  const [history,   setHistory ] = useState([]);
  const [keyPair,   setKeyPair ] = useState(null);
  const [deviceId,  setDeviceId] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [pushToken, setPushToken] = useState(null);
  const [pairingCode, setPairingCode] = useState('');
  const [registered, setRegistered] = useState(false);
  const [deviceInfo, setDeviceInfo] = useState(null);
  const [trustedDevices, setTrustedDevices] = useState([]);
  const [connected, setConnected] = useState(false);
  const [queueSource, setQueueSource] = useState('local');
  const [busy,      setBusy   ] = useState(false);
  const handledRequestIdsRef = useRef(new Set());

  // Initialise keys once
  useEffect(() => {
    let cancelled = false;

    const init = async () => {
      const [kp, currentDeviceId, currentPushToken] = await Promise.all([
        loadOrCreateKeyPair(),
        loadOrCreateDeviceId(),
        getPushToken(),
      ]);
      if (cancelled) return;
      setKeyPair(kp);
      setDeviceId(currentDeviceId);
      setPublicKey(encodePublicKey(kp));
      setPushToken(currentPushToken);
    };

    init().catch(console.error);
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!deviceId || !publicKey) return;

    let cancelled = false;
    const syncRegistration = async () => {
      try {
        const refresh = await refreshDevice({
          device_id: deviceId,
          device_name: `${Platform.OS} kernel`,
          public_key: publicKey,
          push_token: pushToken,
          platform: Platform.OS,
        });
        if (!cancelled && refresh?.ok) {
          setRegistered(true);
          setDeviceInfo({ device_id: deviceId, push_enabled: Boolean(pushToken) });
        }
      } catch {
        // Fall through to broker-side device lookup.
      }

      try {
        const devices = await fetchDevices();
        if (!cancelled) {
          setTrustedDevices(devices.devices ?? []);
        }
        const matched = devices.devices?.find((item) => item.device_id === deviceId);
        if (!cancelled) {
          setRegistered(Boolean(matched));
          setDeviceInfo(matched ?? null);
        }
      } catch {
        if (!cancelled) {
          setRegistered(false);
        }
      }
    };

    syncRegistration();
    return () => { cancelled = true; };
  }, [deviceId, publicKey, pushToken]);

  useEffect(() => {
    if (!registered) {
      setTrustedDevices([]);
      return undefined;
    }

    let cancelled = false;
    const tick = async () => {
      try {
        const devices = await fetchDevices();
        if (cancelled) return;
        const items = devices.devices ?? [];
        setTrustedDevices(items);
        const matched = items.find((item) => item.device_id === deviceId && item.active);
        if (!matched) {
          setRegistered(false);
          setDeviceInfo(null);
          setQueue([]);
          return;
        }
        setDeviceInfo(matched);
      } catch {
        // Device management panel is best-effort.
      }
    };

    tick();
    const id = setInterval(tick, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, [deviceId, registered]);

  // Poll broker first, then fall back to Supabase relay if configured.
  useEffect(() => {
    if (!registered) {
      setQueue([]);
      setQueueSource('local');
      return undefined;
    }
    let cancelled = false;

    const tick = async () => {
      try {
        const pending = await fetchPending();
        if (cancelled) return;
        setConnected(true);
        setQueueSource('local');
        setQueue((prev) => {
          const prevIds = new Set(prev.map((r) => r.id));
          const added   = pending.filter((r) => !prevIds.has(r.id));
          // Also remove items that disappeared from broker (already handled elsewhere)
          const pendingIds = new Set(pending.map((r) => r.id));
          const kept       = prev.filter((r) => pendingIds.has(r.id));
          return [...kept, ...added];
        });
      } catch {
        if (REMOTE_ENABLED && deviceId) {
          try {
            const remotePending = await fetchRemotePending(deviceId);
            if (cancelled) return;
            const filtered = remotePending.filter((item) => !handledRequestIdsRef.current.has(item.id));
            setConnected(true);
            setQueueSource('remote');
            setQueue(filtered);
            return;
          } catch {
            // Fall through to disconnected state.
          }
        }
        if (!cancelled) {
          setConnected(false);
          setQueueSource('local');
        }
      }
    };

    tick();
    const id = setInterval(tick, POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, [deviceId, registered]);

  const handleRegister = useCallback(async () => {
    if (!keyPair || !deviceId || !publicKey) {
      Alert.alert('Device not ready', 'Keypair generation is still in progress.');
      return;
    }
    setBusy(true);
    try {
      const result = await registerDevice({
        pairing_code: pairingCode.trim(),
        device_id: deviceId,
        device_name: `${Platform.OS} kernel`,
        public_key: publicKey,
        push_token: pushToken,
        platform: Platform.OS,
      });
      if (result?.ok) {
        setRegistered(true);
        setPairingCode('');
        setDeviceInfo(result.device ?? { device_id: deviceId, push_enabled: Boolean(pushToken) });
        setTrustedDevices((prev) => {
          const filtered = prev.filter((item) => item.device_id !== deviceId);
          return [...filtered, {
            ...(result.device ?? { device_id: deviceId, device_name: `${Platform.OS} kernel`, platform: Platform.OS, push_enabled: Boolean(pushToken) }),
            active: true,
          }];
        });
        Alert.alert('Device paired', 'This phone is now registered with the broker.');
      } else {
        Alert.alert('Pairing failed', result?.error ?? 'Unknown error');
      }
    } catch (error) {
      Alert.alert('Pairing failed', String(error));
    } finally {
      setBusy(false);
    }
  }, [deviceId, keyPair, pairingCode, publicKey, pushToken]);

  const handleRevokeDevice = useCallback(async (item) => {
    setBusy(true);
    try {
      const result = await revokeDevice(item.device_id);
      if (!result?.ok) {
        Alert.alert('Revoke failed', result?.error ?? 'Unknown error');
        return;
      }
      setTrustedDevices((prev) => prev.map((device) => (
        device.device_id === item.device_id
          ? { ...device, active: false, push_enabled: false }
          : device
      )));
      if (item.device_id === deviceId) {
        setRegistered(false);
        setDeviceInfo(null);
        setQueue([]);
        Alert.alert('Device revoked', 'This device is no longer trusted. Pair it again to continue approving actions.');
      }
    } catch (error) {
      Alert.alert('Revoke failed', String(error));
    } finally {
      setBusy(false);
    }
  }, [deviceId]);

  const handleApprove = useCallback(async (item) => {
    if (!keyPair) return;
    setBusy(true);
    try {
      const auth = await LocalAuthentication.authenticateAsync({
        promptMessage: `Approve: ${item.summary}`,
        fallbackLabel: 'Use PIN',
        cancelLabel:   'Cancel',
      });
      if (!auth.success) { Alert.alert('Authentication failed'); return; }

      const sig  = signRid(keyPair, item.id);
      const resp = item.source === 'remote'
        ? await submitRemoteDecision({
            deviceId,
            requestId: item.id,
            action: 'approve',
            signature: sig,
          })
        : await postApprove(item.id, sig);
      if (resp?.ok) {
        handledRequestIdsRef.current.add(item.id);
        setQueue((q) => q.filter((r) => r.id !== item.id));
        setHistory((h) => [{ ...item, decision: 'approve' }, ...h].slice(0, 20));
      } else {
        Alert.alert('Approval failed', item.source === 'remote' ? 'Remote decision relay returned an error.' : 'Broker returned an error.');
      }
    } catch (e) {
      Alert.alert('Error', String(e));
    } finally {
      setBusy(false);
    }
  }, [deviceId, keyPair]);

  const handleDeny = useCallback(async (item) => {
    setBusy(true);
    try {
      const resp = item.source === 'remote'
        ? await submitRemoteDecision({
            deviceId,
            requestId: item.id,
            action: 'deny',
            signature: null,
          })
        : await postDeny(item.id);
      if (!resp?.ok) {
        Alert.alert('Deny failed', item.source === 'remote' ? 'Remote decision relay returned an error.' : 'Broker returned an error.');
        return;
      }
      handledRequestIdsRef.current.add(item.id);
      setQueue((q)   => q.filter((r) => r.id !== item.id));
      setHistory((h) => [{ ...item, decision: 'deny' }, ...h].slice(0, 20));
    } catch (e) {
      Alert.alert('Error', String(e));
    } finally {
      setBusy(false);
    }
  }, [deviceId]);

  return (
    <View style={styles.root}>
      <StatusBar barStyle="light-content" backgroundColor="#0a0a0f" />

      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Sacred Gatekeeper</Text>
        <View style={[styles.dot, { backgroundColor: connected ? '#27c93f' : '#e83e5a' }]} />
      </View>

      {!registered ? (
        <View style={styles.onboarding}>
          <Text style={styles.onboardingTitle}>Pair this device</Text>
          <Text style={styles.onboardingText}>
            Start the local stack on your laptop, then enter the six-digit pairing code shown by the launcher.
          </Text>
          <TextInput
            value={pairingCode}
            onChangeText={setPairingCode}
            placeholder="123456"
            placeholderTextColor="#5a5a8a"
            keyboardType="number-pad"
            style={styles.input}
            maxLength={6}
          />
          <TouchableOpacity
            style={[styles.btn, styles.btnApprove, (!pairingCode || busy) && styles.btnDisabled]}
            disabled={!pairingCode || busy}
            onPress={handleRegister}
          >
            <Text style={styles.btnText}>Register Device</Text>
          </TouchableOpacity>

          <View style={styles.infoPanel}>
            <Text style={styles.infoLabel}>Broker</Text>
            <Text style={styles.infoValue}>{BROKER_HTTP}</Text>
            <Text style={styles.infoLabel}>Device Id</Text>
            <Text style={styles.infoValue}>{deviceId || 'initialising...'}</Text>
            <Text style={styles.infoLabel}>Push</Text>
            <Text style={styles.infoValue}>
              {pushToken ? 'Expo push token ready' : 'No push token yet. Build/install a dev build or APK and set EXPO_PUBLIC_EXPO_PROJECT_ID.'}
            </Text>
          </View>
        </View>
      ) : null}

      {/* Pending queue */}
      {registered && queue.length === 0 ? (
        <View style={styles.empty}>
          <Text style={styles.emptyIcon}>🔒</Text>
          <Text style={styles.emptyText}>All clear — no pending requests</Text>
          {!connected && (
            <Text style={styles.emptySubtext}>
              Waiting for broker at {BROKER_HTTP}{REMOTE_ENABLED ? ' or Supabase relay' : ''}
            </Text>
          )}
        </View>
      ) : null}

      {registered && queue.length > 0 ? (
        <FlatList
          data={queue}
          keyExtractor={(i) => i.id}
          renderItem={({ item }) => (
            <RequestCard
              item={item}
              onApprove={handleApprove}
              onDeny={handleDeny}
              busy={busy}
            />
          )}
          contentContainerStyle={styles.list}
        />
      ) : null}

      {/* History */}
      {registered && history.length > 0 && (
        <View style={styles.histSection}>
          <Text style={styles.histTitle}>Recent decisions</Text>
          {history.slice(0, 5).map((h) => (
            <HistoryItem key={h.id + h.decision} item={h} />
          ))}
        </View>
      )}

      {registered && deviceInfo ? (
        <View style={styles.deviceBar}>
          <Text style={styles.deviceBarText}>
            Registered as {deviceInfo.device_id} • push {deviceInfo.push_enabled ? 'enabled' : 'not enabled'} • queue {queueSource}
          </Text>
        </View>
      ) : null}

      {registered && trustedDevices.length > 0 ? (
        <View style={styles.deviceSection}>
          <Text style={styles.histTitle}>Trusted devices</Text>
          {trustedDevices.map((item) => (
            <DeviceItem
              key={item.device_id}
              item={item}
              currentDeviceId={deviceId}
              onRevoke={handleRevokeDevice}
              busy={busy}
            />
          ))}
        </View>
      ) : null}

      {busy && (
        <View style={styles.overlay}>
          <ActivityIndicator size="large" color="#e83e5a" />
        </View>
      )}
    </View>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: '#0a0a0f',
    paddingTop: Platform.OS === 'android' ? StatusBar.currentHeight : 48,
  },
  header: {
    flexDirection: 'row',
    alignItems:    'center',
    justifyContent:'space-between',
    paddingHorizontal: 20,
    paddingBottom:      12,
    borderBottomWidth:   1,
    borderBottomColor:  '#1e1e2e',
  },
  headerTitle: {
    color:      '#e0d9ff',
    fontSize:   20,
    fontWeight: '700',
    letterSpacing: 0.8,
  },
  dot: {
    width: 10, height: 10, borderRadius: 5,
  },
  list: { padding: 16, paddingBottom: 32 },
  onboarding: {
    paddingHorizontal: 20,
    paddingTop: 20,
    gap: 12,
  },
  onboardingTitle: {
    color: '#e0d9ff',
    fontSize: 22,
    fontWeight: '700',
  },
  onboardingText: {
    color: '#8f8fb4',
    fontSize: 14,
    lineHeight: 20,
  },
  input: {
    borderWidth: 1,
    borderColor: '#2a2a42',
    borderRadius: 10,
    color: '#f2f2ff',
    fontSize: 22,
    letterSpacing: 6,
    paddingHorizontal: 14,
    paddingVertical: 12,
    backgroundColor: '#13131f',
  },
  infoPanel: {
    backgroundColor: '#13131f',
    borderRadius: 12,
    padding: 14,
    gap: 6,
  },
  infoLabel: {
    color: '#5a5a8a',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: 1,
  },
  infoValue: {
    color: '#d7d7f2',
    fontSize: 13,
  },
  card: {
    backgroundColor: '#13131f',
    borderRadius:    14,
    borderWidth:      2,
    padding:         18,
    marginBottom:    16,
  },
  riskBadge: {
    alignSelf:    'flex-start',
    borderRadius:  6,
    paddingHorizontal: 10,
    paddingVertical:    4,
    marginBottom:  10,
  },
  riskText:  { color: '#000', fontWeight: '800', fontSize: 11, letterSpacing: 1.2 },
  summary:   { color: '#e0d9ff', fontSize: 17, fontWeight: '600', marginBottom: 6 },
  rid:       { color: '#4a4a6a', fontSize: 11, marginBottom: 14 },
  btnRow:    { flexDirection: 'row', gap: 10 },
  btn: {
    flex: 1, paddingVertical: 13, borderRadius: 10, alignItems: 'center',
  },
  btnApprove:  { backgroundColor: '#1a3d2b' },
  btnDeny:     { backgroundColor: '#3d1a1a' },
  btnDisabled: { opacity: 0.4 },
  btnText:     { color: '#e0d9ff', fontWeight: '700', fontSize: 15 },
  empty: {
    flex: 1, alignItems: 'center', justifyContent: 'center', gap: 12,
  },
  emptyIcon:    { fontSize: 48 },
  emptyText:    { color: '#5a5a8a', fontSize: 17, fontWeight: '600' },
  emptySubtext: { color: '#3a3a5a', fontSize: 13 },
  histSection: {
    borderTopWidth:  1,
    borderTopColor: '#1e1e2e',
    paddingHorizontal: 20,
    paddingTop:         12,
    paddingBottom:      24,
  },
  deviceSection: {
    borderTopWidth: 1,
    borderTopColor: '#1e1e2e',
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 16,
    gap: 8,
  },
  histTitle: { color: '#5a5a8a', fontSize: 12, fontWeight: '700', marginBottom: 8, letterSpacing: 0.8 },
  histRow:   { flexDirection: 'row', alignItems: 'center', paddingVertical: 5, gap: 8 },
  histSymbol: { fontSize: 14, fontWeight: '700', width: 18 },
  histText:   { flex: 1, color: '#a0a0c0', fontSize: 13 },
  histRisk:   { fontSize: 11, fontWeight: '700' },
  deviceRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#13131f',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    gap: 10,
  },
  deviceRowMain: {
    flex: 1,
    gap: 2,
  },
  deviceName: {
    color: '#e0d9ff',
    fontSize: 14,
    fontWeight: '600',
  },
  deviceMeta: {
    color: '#8f8fb4',
    fontSize: 12,
  },
  smallButton: {
    backgroundColor: '#3d1a1a',
    borderRadius: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  smallButtonText: {
    color: '#f0dede',
    fontSize: 12,
    fontWeight: '700',
  },
  overlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(10,10,15,0.7)',
    alignItems:       'center',
    justifyContent:   'center',
  },
  deviceBar: {
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderTopWidth: 1,
    borderTopColor: '#1e1e2e',
    backgroundColor: '#10101a',
  },
  deviceBarText: {
    color: '#8f8fb4',
    fontSize: 12,
  },
});

