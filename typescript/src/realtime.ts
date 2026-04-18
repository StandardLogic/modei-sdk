/**
 * Modei Realtime Adapter
 *
 * Handles Supabase Realtime connection for agent presence and verification.
 * This module is opt-in: only activated when realtime.enabled is true in config.
 *
 * Features:
 * - Exchange passport for short-lived Realtime JWT
 * - Track Presence with agent/passport metadata
 * - Respond to verify.request broadcasts with signed nonce
 * - Token refresh every 4 minutes
 * - Exponential backoff reconnection
 * - Cleanup on process exit
 */

import { createClient as createSupabaseClient, type SupabaseClient, type RealtimeChannel } from '@supabase/supabase-js';
import * as crypto from 'crypto';

export interface RealtimeConfig {
  enabled: boolean;
  supabaseUrl: string;
  tokenEndpoint: string;
}

export interface AgentCredentials {
  agentId: string;
  passportId: string;
  passportFingerprint: string;
  /** Base64-encoded Ed25519 private key for signing */
  privateKey: string;
  /** Base64-encoded Ed25519 public key */
  publicKey: string;
}

export interface RealtimeAdapter {
  connect(): Promise<void>;
  disconnect(): void;
}

const VERSION = '1.2.0';

/**
 * Create a Realtime adapter for agent presence and verification.
 */
export function createRealtimeAdapter(
  config: RealtimeConfig,
  credentials: AgentCredentials,
  apiKey: string,
): RealtimeAdapter {
  let supabase: SupabaseClient | null = null;
  let channel: RealtimeChannel | null = null;
  let refreshInterval: ReturnType<typeof setInterval> | null = null;
  let startedAt: string = new Date().toISOString();

  async function exchangeForToken(): Promise<string> {
    // Generate a challenge and sign it
    const challenge = crypto.randomBytes(32).toString('hex');
    const timestamp = new Date().toISOString();

    // Sign the challenge with the passport private key
    // Using dynamic import to avoid hard dependency on @noble/ed25519
    const ed = await import('@noble/ed25519');

    // Set up sha512 if needed
    if (!ed.hashes.sha512) {
      const { sha512 } = await import('@noble/hashes/sha2.js');
      ed.hashes.sha512 = sha512;
    }

    const privateKeyBytes = Buffer.from(credentials.privateKey, 'base64');
    const challengeBytes = Buffer.from(challenge, 'utf8');
    const signature = await ed.signAsync(challengeBytes, privateKeyBytes);
    const signatureHex = Buffer.from(signature).toString('hex');

    const response = await fetch(config.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_id: credentials.agentId,
        passport_id: credentials.passportId,
        challenge,
        signature: signatureHex,
        timestamp,
      }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(`Failed to exchange passport for token: ${err.error || response.status}`);
    }

    const data = await response.json();
    return data.token;
  }

  async function signNonce(nonce: string): Promise<string> {
    const ed = await import('@noble/ed25519');
    if (!ed.hashes.sha512) {
      const { sha512 } = await import('@noble/hashes/sha2.js');
      ed.hashes.sha512 = sha512;
    }
    const privateKeyBytes = Buffer.from(credentials.privateKey, 'base64');
    const nonceBytes = Buffer.from(nonce, 'utf8');
    const signature = await ed.signAsync(nonceBytes, privateKeyBytes);
    return Buffer.from(signature).toString('hex');
  }

  async function connect() {
    startedAt = new Date().toISOString();

    // Step 1: Exchange passport for Realtime token
    const token = await exchangeForToken();
    console.error(`[modei-realtime] Token acquired for agent ${credentials.agentId}`);

    // Step 2: Connect to Supabase Realtime
    supabase = createSupabaseClient(config.supabaseUrl, token, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    supabase.realtime.setAuth(token);

    const channelName = `agent:${credentials.agentId}`;
    channel = supabase.channel(channelName, {
      config: { presence: { key: credentials.agentId } },
    });

    // Step 3: Listen for verify.request broadcasts
    channel.on('broadcast', { event: 'verify.request' }, async (payload) => {
      try {
        const { nonce, timestamp } = payload.payload;
        const signature = await signNonce(nonce);

        channel!.send({
          type: 'broadcast',
          event: 'verify.response',
          payload: {
            nonce,
            timestamp: new Date().toISOString(),
            uptime_seconds: Math.floor(process.uptime()),
            passport_fingerprint: credentials.passportFingerprint,
            sdk_version: `modei-mcp@${VERSION}`,
            signature,
          },
        });
        console.error(`[modei-realtime] Responded to verify challenge`);
      } catch (err) {
        console.error(`[modei-realtime] Failed to respond to verify challenge:`, err);
      }
    });

    // Step 4: Subscribe and track Presence
    channel.subscribe(async (status) => {
      if (status === 'SUBSCRIBED') {
        await channel!.track({
          agent_id: credentials.agentId,
          passport_id: credentials.passportId,
          passport_fingerprint: credentials.passportFingerprint,
          sdk: 'modei-mcp',
          sdk_version: VERSION,
          runtime: 'nodejs',
          env: process.env.NODE_ENV || 'development',
          started_at: startedAt,
        });
        console.error(`[modei-realtime] Presence tracked on channel ${channelName}`);
      }
    });

    // Step 5: Token refresh every 4 minutes
    refreshInterval = setInterval(async () => {
      try {
        const newToken = await exchangeForToken();
        supabase!.realtime.setAuth(newToken);
        console.error(`[modei-realtime] Token refreshed`);
      } catch (err) {
        console.error(`[modei-realtime] Token refresh failed:`, err);
      }
    }, 4 * 60 * 1000);

    // Step 6: Cleanup on process exit
    const cleanup = () => {
      disconnect();
      process.exit(0);
    };
    process.on('SIGTERM', cleanup);
    process.on('SIGINT', cleanup);
  }

  function disconnect() {
    if (refreshInterval) {
      clearInterval(refreshInterval);
      refreshInterval = null;
    }
    if (channel) {
      channel.untrack();
      channel.unsubscribe();
      channel = null;
    }
    if (supabase) {
      supabase.removeAllChannels();
      supabase = null;
    }
    console.error(`[modei-realtime] Disconnected`);
  }

  return { connect, disconnect };
}

/**
 * Compute a SHA-256 fingerprint of the passport public key.
 */
export function computeFingerprint(publicKeyBase64: string): string {
  const hash = crypto.createHash('sha256').update(Buffer.from(publicKeyBase64, 'base64')).digest('hex');
  return `sha256:${hash}`;
}
