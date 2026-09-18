/**
 * PoC: Sensitive Authentication Material Logged Without Redaction
 *
 * This test proves that RequestLogger middleware logs full request bodies
 * including sensitive authentication fields (OIDC tokens, passkey attestations,
 * wallet signatures, Firebase tokens) without any field-level redaction.
 *
 * Attacker model: Insider/operator with log access (Datadog, SIEM, CloudWatch)
 * can extract these credentials and potentially replay them within their TTL.
 *
 * Note: the middleware logs via logger.debug (lowest syslog level; LOG_LEVEL
 * defaults to 'debug' in @dydxprotocol-indexer/base config), so we spy on
 * logger.debug.
 */

import { logger, safeJsonStringify } from '@dydxprotocol-indexer/base';
import express from 'express';
import request from 'supertest';

// Spy on logger.debug to capture what gets logged (middleware logs at debug level)
const loggerDebugSpy = jest.spyOn(logger, 'debug');

// Import the actual RequestLogger middleware
import RequestLogger from '../../src/request-helpers/request-logger';

describe('PoC: Sensitive auth material logged without redaction', () => {
  let app: express.Express;

  beforeAll(() => {
    app = express();
    app.use(express.json());
    app.use(RequestLogger);

    // Mock routes that accept sensitive data
    app.post('/v4/turnkey/signin', (_req, res) => {
      res.status(200).json({ success: true });
    });
    app.post('/v4/turnkey/uploadAddress', (_req, res) => {
      res.status(200).json({ success: true });
    });
    app.post('/v4/addresses/:address/registerToken', (_req, res) => {
      res.status(200).json({ success: true });
    });
  });

  beforeEach(() => {
    loggerDebugSpy.mockClear();
  });

  it('logs OIDC token from /turnkey/signin social auth in plaintext', async () => {
    const sensitiveOidcToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.SENSITIVE_GOOGLE_OIDC_TOKEN_PAYLOAD.signature';
    const sensitiveTargetPublicKey = '04a1b2c3d4e5f6...user_public_key_material';

    await request(app)
      .post('/v4/turnkey/signin')
      .send({
        signinMethod: 'social',
        provider: 'google',
        oidcToken: sensitiveOidcToken,
        targetPublicKey: sensitiveTargetPublicKey,
      });

    // Verify logger.debug was called
    expect(loggerDebugSpy).toHaveBeenCalled();

    // Extract the logged message
    const loggedCall = loggerDebugSpy.mock.calls[0][0] as any;
    const loggedBody = loggedCall.message.request.body;

    // VULNERABILITY: Full OIDC token appears in logs without redaction
    expect(loggedBody).toContain(sensitiveOidcToken);
    expect(loggedBody).toContain(sensitiveTargetPublicKey);
    expect(loggedBody).toContain('google');

    // Prove no redaction occurred
    expect(loggedBody).not.toContain('[REDACTED]');
    expect(loggedBody).not.toContain('***');

    console.log('\n=== LOGGED SENSITIVE DATA (would appear in Datadog/SIEM) ===');
    console.log('Body:', loggedBody);
    console.log('============================================================\n');
  });

  it('logs passkey attestation from /turnkey/signin in plaintext', async () => {
    const sensitiveAttestation = {
      credentialId: 'abc123-credential-id-from-authenticator',
      clientDataJSON: 'base64_encoded_client_data_with_origin_and_challenge',
      attestationObject: 'base64_encoded_attestation_with_public_key_and_signature',
      transports: ['usb', 'nfc'],
    };

    await request(app)
      .post('/v4/turnkey/signin')
      .send({
        signinMethod: 'passkey',
        challenge: 'random_challenge_string_12345',
        attestation: sensitiveAttestation,
      });

    expect(loggerDebugSpy).toHaveBeenCalled();

    const loggedCall = loggerDebugSpy.mock.calls[0][0] as any;
    const loggedBody = loggedCall.message.request.body;

    // VULNERABILITY: Full passkey attestation appears in logs
    expect(loggedBody).toContain('credentialId');
    expect(loggedBody).toContain('abc123-credential-id-from-authenticator');
    expect(loggedBody).toContain('attestationObject');
    expect(loggedBody).toContain('base64_encoded_attestation_with_public_key_and_signature');

    console.log('\n=== LOGGED PASSKEY ATTESTATION ===');
    console.log('Body:', loggedBody);
    console.log('===================================\n');
  });

  it('logs wallet signature from /turnkey/uploadAddress in plaintext', async () => {
    const sensitiveDydxAddress = 'dydx1abc123456789victim_address';
    const sensitiveWalletSignature = '0x1234567890abcdef...wallet_signed_message_proving_ownership';

    await request(app)
      .post('/v4/turnkey/uploadAddress')
      .send({
        dydxAddress: sensitiveDydxAddress,
        signature: sensitiveWalletSignature,
      });

    expect(loggerDebugSpy).toHaveBeenCalled();

    const loggedCall = loggerDebugSpy.mock.calls[0][0] as any;
    const loggedBody = loggedCall.message.request.body;

    // VULNERABILITY: Wallet signature appears in logs
    expect(loggedBody).toContain(sensitiveWalletSignature);
    expect(loggedBody).toContain(sensitiveDydxAddress);

    console.log('\n=== LOGGED WALLET SIGNATURE ===');
    console.log('Body:', loggedBody);
    console.log('================================\n');
  });

  it('logs Firebase push token from /addresses/:address/registerToken in plaintext', async () => {
    const sensitiveFirebaseToken = 'fMC7abc123:APA91b...firebase_cloud_messaging_device_token';

    await request(app)
      .post('/v4/addresses/dydx1victim/registerToken')
      .send({
        token: sensitiveFirebaseToken,
        language: 'en',
      });

    expect(loggerDebugSpy).toHaveBeenCalled();

    const loggedCall = loggerDebugSpy.mock.calls[0][0] as any;
    const loggedBody = loggedCall.message.request.body;

    // VULNERABILITY: Firebase token appears in logs (enables push notification abuse)
    expect(loggedBody).toContain(sensitiveFirebaseToken);

    console.log('\n=== LOGGED FIREBASE TOKEN ===');
    console.log('Body:', loggedBody);
    console.log('==============================\n');
  });

  it('logs all request headers including Authorization if present', async () => {
    const sensitiveAuthHeader = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_jwt_payload';

    await request(app)
      .post('/v4/turnkey/signin')
      .set('Authorization', sensitiveAuthHeader)
      .set('Cookie', 'session=abc123; secret=xyz789')
      .send({ signinMethod: 'email', userEmail: 'test@example.com' });

    expect(loggerDebugSpy).toHaveBeenCalled();

    const loggedCall = loggerDebugSpy.mock.calls[0][0] as any;
    const loggedHeaders = loggedCall.message.request.headers;

    // VULNERABILITY: Authorization header logged in full
    expect(loggedHeaders.authorization).toBe(sensitiveAuthHeader);
    expect(loggedHeaders.cookie).toContain('session=abc123');

    console.log('\n=== LOGGED HEADERS ===');
    console.log('Authorization:', loggedHeaders.authorization);
    console.log('Cookie:', loggedHeaders.cookie);
    console.log('=======================\n');
  });

  it('proves safeJsonStringify does NOT redact sensitive fields', () => {
    const sensitivePayload = {
      oidcToken: 'SENSITIVE_OIDC_TOKEN_VALUE',
      password: 'user_password_123',
      apiKey: 'sk_live_secret_key',
      signature: '0xdeadbeef...',
      attestation: { credentialId: 'secret_cred' },
    };

    const stringified = safeJsonStringify(sensitivePayload);

    // All sensitive values appear in output - NO redaction
    expect(stringified).toContain('SENSITIVE_OIDC_TOKEN_VALUE');
    expect(stringified).toContain('user_password_123');
    expect(stringified).toContain('sk_live_secret_key');
    expect(stringified).toContain('0xdeadbeef');
    expect(stringified).toContain('secret_cred');

    // Confirm no redaction markers
    expect(stringified).not.toContain('[REDACTED]');
    expect(stringified).not.toContain('***');
    expect(stringified).not.toContain('[FILTERED]');

    console.log('\n=== safeJsonStringify OUTPUT (no redaction) ===');
    console.log(stringified);
    console.log('================================================\n');
  });
});
