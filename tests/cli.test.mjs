import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  runCli,
  parseArgs,
  formatRecordsTable,
  formatDnssecStatus,
  formatTsigKeysList,
  formatDomainTsigPermissions,
  setApiKey,
  getApiKey,
  getStoredApiToken,
  loadConfig,
  clearConfig,
  getConfigFilePath,
} from '../dist/index.js';

function createCapture() {
  const stdoutLines = [];
  const stderrLines = [];
  return {
    stdout: (msg) => stdoutLines.push(String(msg)),
    stderr: (msg) => stderrLines.push(String(msg)),
    getStdout: () => stdoutLines.join('\n'),
    getStderr: () => stderrLines.join('\n'),
  };
}

test('CLI argument parser handles flags and subcommands correctly', () => {
  const parsed = parseArgs([
    '--api-key', 'custom_key',
    '--json',
    '--timeout', '45',
    'records',
    'add',
    'example.com',
    '--name', 'api',
    '--type', 'A',
    '--value', '192.0.2.1',
    '--value', '192.0.2.2',
    '--ttl', '300',
  ]);

  assert.equal(parsed.command, 'records');
  assert.equal(parsed.action, 'add');
  assert.equal(parsed.apiKey, 'custom_key');
  assert.equal(parsed.json, true);
  assert.equal(parsed.timeout, 45);
  assert.deepEqual(parsed.positionals, ['example.com']);
  assert.equal(parsed.options.name, 'api');
  assert.equal(parsed.options.type, 'A');
  assert.deepEqual(parsed.options.value, ['192.0.2.1', '192.0.2.2']);
  assert.equal(parsed.options.ttl, 300);

  const parsedTsig = parseArgs([
    'tsig',
    'set-permissions',
    'example.com',
    'key1',
    '--update',
    '--subdomain', '_acme_challenge',
    '-s', 'staging',
  ]);
  assert.equal(parsedTsig.command, 'tsig');
  assert.equal(parsedTsig.action, 'set-permissions');
  assert.deepEqual(parsedTsig.positionals, ['example.com', 'key1']);
  assert.equal(parsedTsig.options.update, true);
  assert.deepEqual(parsedTsig.options.subdomain, ['_acme_challenge', 'staging']);
});

test('CLI shows version on --version or -V', async () => {
  const cap = createCapture();
  const code = await runCli(['--version'], cap);
  assert.equal(code, 0);
  assert.match(cap.getStdout(), /@onlydns\/cli 1\.0\.2/);

  const cap2 = createCapture();
  const code2 = await runCli(['-V'], cap2);
  assert.equal(code2, 0);
  assert.match(cap2.getStdout(), /@onlydns\/cli 1\.0\.2/);
});

test('CLI shows help on --help or missing command', async () => {
  const cap = createCapture();
  const code = await runCli(['--help'], cap);
  assert.equal(code, 0);
  assert.match(cap.getStdout(), /usage: onlydns/);
  assert.match(cap.getStdout(), /domains/);
  assert.match(cap.getStdout(), /records/);
  assert.match(cap.getStdout(), /dnssec/);
  assert.match(cap.getStdout(), /tsig/);
  assert.match(cap.getStdout(), /config/);

  const capEmpty = createCapture();
  const codeEmpty = await runCli([], capEmpty);
  assert.equal(codeEmpty, 0);
  assert.match(capEmpty.getStdout(), /usage: onlydns/);
});

test('CLI shows subcommand specific help', async () => {
  const capDomains = createCapture();
  await runCli(['domains', '--help'], capDomains);
  assert.match(capDomains.getStdout(), /Domain management commands/);

  const capRecords = createCapture();
  await runCli(['records', '--help'], capRecords);
  assert.match(capRecords.getStdout(), /DNS record management commands/);

  const capDnssec = createCapture();
  await runCli(['dnssec', '--help'], capDnssec);
  assert.match(capDnssec.getStdout(), /DNSSEC lifecycle management commands/);

  const capTsig = createCapture();
  await runCli(['tsig', '--help'], capTsig);
  assert.match(capTsig.getStdout(), /TSIG key management commands/);

  const capConfig = createCapture();
  await runCli(['config', '--help'], capConfig);
  assert.match(capConfig.getStdout(), /Configuration and credential management commands/);
});

test('CLI config management: set-key, get-key, path, and clear', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'onlydns-test-config-'));
  const originalXdg = process.env.XDG_CONFIG_HOME;
  const originalKey = process.env.ONLYDNS_API_KEY;
  const originalToken = process.env.ONLYDNS_API_TOKEN;

  try {
    process.env.XDG_CONFIG_HOME = tempDir;
    delete process.env.ONLYDNS_API_KEY;
    delete process.env.ONLYDNS_API_TOKEN;

    // 1. Path command
    const capPath = createCapture();
    const codePath = await runCli(['config', 'path'], capPath);
    assert.equal(codePath, 0);
    assert.match(capPath.getStdout(), /config\.json/);

    // 2. Set key
    const capSet = createCapture();
    const codeSet = await runCli(['config', 'set-key', 'secret_token_12345'], capSet);
    assert.equal(codeSet, 0);
    assert.match(capSet.getStdout(), /API key successfully saved/);

    // Check stored value
    assert.equal(getStoredApiToken(), 'secret_token_12345');
    assert.equal(getApiKey(), 'secret_token_12345');

    // 3. Get key (masked)
    const capGet = createCapture();
    const codeGet = await runCli(['config', 'get-key'], capGet);
    assert.equal(codeGet, 0);
    assert.match(capGet.getStdout(), /Active API key: secr\*+2345/);

    // 4. Get key with --json
    const capGetJson = createCapture();
    const codeGetJson = await runCli(['config', 'get-key', '--json'], capGetJson);
    assert.equal(codeGetJson, 0);
    const parsedJson = JSON.parse(capGetJson.getStdout());
    assert.equal(parsedJson.stored_key_present, true);
    assert.equal(parsedJson.active_key_present, true);

    // 5. Clear key
    const capClear = createCapture();
    const codeClear = await runCli(['config', 'clear'], capClear);
    assert.equal(codeClear, 0);
    assert.match(capClear.getStdout(), /Configuration file cleared/);
    assert.equal(getStoredApiToken(), undefined);

    // 6. Missing key error
    const capMissing = createCapture();
    const codeMissing = await runCli(['config', 'set-key'], capMissing);
    assert.equal(codeMissing, 2);
    assert.match(capMissing.getStderr(), /API key is required/);
  } finally {
    if (originalXdg !== undefined) process.env.XDG_CONFIG_HOME = originalXdg;
    else delete process.env.XDG_CONFIG_HOME;
    if (originalKey !== undefined) process.env.ONLYDNS_API_KEY = originalKey;
    if (originalToken !== undefined) process.env.ONLYDNS_API_TOKEN = originalToken;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('CLI domains commands with mocked responses', async () => {
  const originalFetch = globalThis.fetch;
  try {
    // 1. List domains
    globalThis.fetch = async (url) => {
      if (url.includes('/dns?')) {
        return {
          status: 200,
          ok: true,
          text: async () => JSON.stringify(['example.com', 'test.net']),
          json: async () => ['example.com', 'test.net'],
        };
      }
      return { status: 404, ok: false, text: async () => JSON.stringify({ title: 'Not Found' }), json: async () => ({ title: 'Not Found' }) };
    };

    const capList = createCapture();
    const codeList = await runCli(['--api-key', 'mock_token', 'domains', 'list'], capList);
    assert.equal(codeList, 0);
    assert.match(capList.getStdout(), /Domains \(2\):/);
    assert.match(capList.getStdout(), /example\.com/);
    assert.match(capList.getStdout(), /test\.net/);

    // 2. List domains JSON
    const capListJson = createCapture();
    const codeListJson = await runCli(['--api-key', 'mock_token', 'domains', 'list', '--json'], capListJson);
    assert.equal(codeListJson, 0);
    const parsedList = JSON.parse(capListJson.getStdout());
    assert.deepEqual(parsedList, ['example.com', 'test.net']);

    // 3. Create domain
    let createdDomainPayload = null;
    globalThis.fetch = async (url, opts) => {
      if (opts.method === 'POST' && url.endsWith('/dns')) {
        createdDomainPayload = JSON.parse(opts.body);
        return { status: 200, ok: true, text: async () => JSON.stringify({}), json: async () => ({}) };
      }
      return { status: 400, ok: false, text: async () => JSON.stringify({ title: 'Error' }), json: async () => ({ title: 'Error' }) };
    };

    const capCreate = createCapture();
    const codeCreate = await runCli(['--api-key', 'mock_token', 'domains', 'create', 'newdomain.org'], capCreate);
    assert.equal(codeCreate, 0);
    assert.deepEqual(createdDomainPayload, { domain: 'newdomain.org' });
    assert.match(capCreate.getStdout(), /Successfully created domain 'newdomain\.org'/);

    // 4. Missing domain parameter
    const capErr = createCapture();
    const codeErr = await runCli(['--api-key', 'mock_token', 'domains', 'create'], capErr);
    assert.equal(codeErr, 2);
    assert.match(capErr.getStderr(), /Domain name is required/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('CLI records commands: list, find with substring matching, add, update, remove', async () => {
  const originalFetch = globalThis.fetch;
  const mockRecords = [
    { name: 'api.example.com.', type: 'A', ttl: 300, records: ['192.0.2.1'] },
    { name: 'mail.example.com.', type: 'A', ttl: 300, records: ['192.0.2.25'] },
    { name: 'www.example.com.', type: 'CNAME', ttl: 600, records: ['example.com.'] },
    { name: 'example.com.', type: 'TXT', ttl: 300, records: ['v=spf1 include:_spf.example.com ~all'] },
  ];

  try {
    globalThis.fetch = async (url, opts) => {
      if ((opts?.method || 'GET') === 'GET' && url.includes('/dns/example.com/records')) {
        return {
          status: 200,
          ok: true,
          text: async () => JSON.stringify(mockRecords),
          json: async () => mockRecords,
        };
      }
      if (opts?.method === 'PUT' && url.includes('/dns/example.com/records')) {
        return {
          status: 200,
          ok: true,
          text: async () => opts.body,
          json: async () => JSON.parse(opts.body),
        };
      }
      return { status: 404, ok: false, text: async () => JSON.stringify({ title: 'Not Found' }), json: async () => ({ title: 'Not Found' }) };
    };

    // 1. Records list
    const capList = createCapture();
    const codeList = await runCli(['--api-key', 'mock_token', 'records', 'list', 'example.com'], capList);
    assert.equal(codeList, 0);
    assert.match(capList.getStdout(), /NAME\s+TYPE\s+TTL\s+VALUES/);
    assert.match(capList.getStdout(), /api\.example\.com\.\s+A\s+300\s+192\.0\.2\.1/);

    // 2. Records find by name substring
    const capFindName = createCapture();
    const codeFindName = await runCli(['--api-key', 'mock_token', 'records', 'find', 'example.com', '--name', 'api'], capFindName);
    assert.equal(codeFindName, 0);
    assert.match(capFindName.getStdout(), /api\.example\.com\./);
    assert.doesNotMatch(capFindName.getStdout(), /mail\.example\.com\./);

    // 3. Records find by type
    const capFindType = createCapture();
    const codeFindType = await runCli(['--api-key', 'mock_token', 'records', 'find', 'example.com', '--type', 'TXT'], capFindType);
    assert.equal(codeFindType, 0);
    assert.match(capFindType.getStdout(), /v=spf1/);

    // 4. Records find by value substring
    const capFindVal = createCapture();
    const codeFindVal = await runCli(['--api-key', 'mock_token', 'records', 'find', 'example.com', '--value', '192.0.2.25'], capFindVal);
    assert.equal(codeFindVal, 0);
    assert.match(capFindVal.getStdout(), /mail\.example\.com\./);

    // 5. Records find without any filters -> Error code 2
    const capFindNoFilter = createCapture();
    const codeFindNoFilter = await runCli(['--api-key', 'mock_token', 'records', 'find', 'example.com'], capFindNoFilter);
    assert.equal(codeFindNoFilter, 2);
    assert.match(capFindNoFilter.getStderr(), /At least one filter option \(--name, --type, or --value\) is required/);

    // 6. Records add
    const capAdd = createCapture();
    const codeAdd = await runCli([
      '--api-key', 'mock_token',
      'records', 'add', 'example.com',
      '--name', 'blog',
      '--type', 'A',
      '--value', '192.0.2.50',
      '--ttl', '300',
    ], capAdd);
    assert.equal(codeAdd, 0);
    assert.match(capAdd.getStdout(), /Added record blog A -> 192\.0\.2\.50 \(TTL 300\)/);

    // 7. Records update
    const capUpdate = createCapture();
    const codeUpdate = await runCli([
      '--api-key', 'mock_token',
      'records', 'update', 'example.com',
      '-n', 'api',
      '-t', 'A',
      '-v', '192.0.2.100',
    ], capUpdate);
    assert.equal(codeUpdate, 0);
    assert.match(capUpdate.getStdout(), /Updated record api A -> 192\.0\.2\.100/);

    // 8. Records remove
    const capRemove = createCapture();
    const codeRemove = await runCli([
      '--api-key', 'mock_token',
      'records', 'remove', 'example.com',
      '-n', 'api',
      '-t', 'A',
    ], capRemove);
    assert.equal(codeRemove, 0);
    assert.match(capRemove.getStdout(), /Removed record api A from 'example\.com'/);

    // 9. Records missing action / domain
    const capMissingAction = createCapture();
    const codeMissingAction = await runCli(['--api-key', 'mock_token', 'records'], capMissingAction);
    assert.equal(codeMissingAction, 2);
    assert.match(capMissingAction.getStderr(), /Please specify a records action/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('CLI DNSSEC commands: status, enable, disable', async () => {
  const originalFetch = globalThis.fetch;
  const mockStatus = {
    enabled: true,
    nsec3param: '1 0 10 abcd',
    keys: [
      {
        keyTag: 2371,
        algorithm: 13,
        digestType: 2,
        digest: '4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E',
      },
    ],
  };

  try {
    globalThis.fetch = async (url, opts) => {
      const method = opts?.method || 'GET';
      if (method === 'GET' && url.includes('/dnssec')) {
        return {
          status: 200,
          ok: true,
          text: async () => JSON.stringify(mockStatus),
          json: async () => mockStatus,
        };
      }
      if (method === 'POST' && url.includes('/dnssec')) {
        return { status: 200, ok: true, text: async () => JSON.stringify({}), json: async () => ({}) };
      }
      if (method === 'DELETE' && url.includes('/dnssec')) {
        return { status: 204, ok: true, text: async () => '' };
      }
      return { status: 400, ok: false, text: async () => JSON.stringify({ title: 'Error' }), json: async () => ({ title: 'Error' }) };
    };

    // 1. DNSSEC Status
    const capStatus = createCapture();
    const codeStatus = await runCli(['--api-key', 'mock_token', 'dnssec', 'status', 'example.com'], capStatus);
    assert.equal(codeStatus, 0);
    assert.match(capStatus.getStdout(), /DNSSEC Status for example\.com:/);
    assert.match(capStatus.getStdout(), /Enabled:\s+true/);
    assert.match(capStatus.getStdout(), /KeyTag: 2371/);

    // 2. DNSSEC Status JSON
    const capStatusJson = createCapture();
    const codeStatusJson = await runCli(['--api-key', 'mock_token', 'dnssec', 'status', 'example.com', '--json'], capStatusJson);
    assert.equal(codeStatusJson, 0);
    const parsed = JSON.parse(capStatusJson.getStdout());
    assert.equal(parsed.enabled, true);
    assert.equal(parsed.keys[0].keyTag, 2371);

    // 3. DNSSEC Enable
    const capEnable = createCapture();
    const codeEnable = await runCli(['--api-key', 'mock_token', 'dnssec', 'enable', 'example.com'], capEnable);
    assert.equal(codeEnable, 0);
    assert.match(capEnable.getStdout(), /DNSSEC successfully enabled for 'example\.com'/);

    // 4. DNSSEC Disable
    const capDisable = createCapture();
    const codeDisable = await runCli(['--api-key', 'mock_token', 'dnssec', 'disable', 'example.com'], capDisable);
    assert.equal(codeDisable, 0);
    assert.match(capDisable.getStdout(), /DNSSEC successfully disabled for 'example\.com'/);

    // 5. DNSSEC missing action
    const capErr = createCapture();
    const codeErr = await runCli(['--api-key', 'mock_token', 'dnssec'], capErr);
    assert.equal(codeErr, 2);
    assert.match(capErr.getStderr(), /Please specify a dnssec action/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('CLI TSIG commands: list, create, get, get-domain, set-permissions, clear', async () => {
  const originalFetch = globalThis.fetch;
  const mockKeys = [
    { name: 'primary-key', algorithm: 'hmac-sha256', key: 'secret1==' },
    { name: 'secondary-key', algorithm: 'hmac-sha512', key: 'secret2==' },
  ];
  let lastPatchBody = null;

  try {
    globalThis.fetch = async (url, opts) => {
      const method = opts?.method || 'GET';
      if (method === 'GET' && url.endsWith('/dns/tsig')) {
        return {
          status: 200,
          ok: true,
          text: async () => JSON.stringify({ tsigKeys: mockKeys }),
          json: async () => ({ tsigKeys: mockKeys }),
        };
      }
      if (method === 'POST' && url.endsWith('/dns/tsig')) {
        const res = {
          name: 'generated-key-123',
          algorithm: 'hmac-sha256',
          key: 'generated_secret==',
        };
        return {
          status: 200,
          ok: true,
          text: async () => JSON.stringify(res),
          json: async () => res,
        };
      }
      if (method === 'GET' && url.includes('/dns/tsig/primary-key')) {
        const res = {
          name: 'primary-key',
          algorithm: 'hmac-sha256',
          key: 'secret1==',
        };
        return {
          status: 200,
          ok: true,
          text: async () => JSON.stringify(res),
          json: async () => res,
        };
      }
      if (method === 'GET' && url.endsWith('/dns/example.com/tsig')) {
        const res = {
          'primary-key': {
            allowAxfr: true,
            allowDnsUpdate: true,
            subdomains: ['_acme-challenge', 'staging'],
          },
        };
        return {
          status: 200,
          ok: true,
          text: async () => JSON.stringify(res),
          json: async () => res,
        };
      }
      if (method === 'PATCH' && url.includes('/tsig/')) {
        lastPatchBody = JSON.parse(opts.body);
        return { status: 200, ok: true, text: async () => JSON.stringify({}), json: async () => ({}) };
      }
      if (method === 'DELETE' && url.endsWith('/tsig')) {
        return { status: 204, ok: true, text: async () => '' };
      }
      return { status: 400, ok: false, text: async () => JSON.stringify({ title: 'Error' }), json: async () => ({ title: 'Error' }) };
    };

    // 1. TSIG List
    const capList = createCapture();
    const codeList = await runCli(['--api-key', 'mock_token', 'tsig', 'list'], capList);
    assert.equal(codeList, 0);
    assert.match(capList.getStdout(), /TSIG Keys \(2\):/);
    assert.match(capList.getStdout(), /primary-key/);

    // 2. TSIG Create
    const capCreate = createCapture();
    const codeCreate = await runCli(['--api-key', 'mock_token', 'tsig', 'create', '--algo', 'hmac-sha256'], capCreate);
    assert.equal(codeCreate, 0);
    assert.match(capCreate.getStdout(), /Created TSIG key 'generated-key-123'/);

    // 3. TSIG Get
    const capGet = createCapture();
    const codeGet = await runCli(['--api-key', 'mock_token', 'tsig', 'get', 'primary-key'], capGet);
    assert.equal(codeGet, 0);
    assert.match(capGet.getStdout(), /TSIG Key 'primary-key':/);
    assert.match(capGet.getStdout(), /Secret:\s+secret1==/);

    // 4. TSIG Get Domain Permissions
    const capGetDomain = createCapture();
    const codeGetDomain = await runCli(['--api-key', 'mock_token', 'tsig', 'get-domain', 'example.com'], capGetDomain);
    assert.equal(codeGetDomain, 0);
    assert.match(capGetDomain.getStdout(), /TSIG Key Permissions for domain 'example\.com':/);
    assert.match(capGetDomain.getStdout(), /primary-key\s+AXFR=true, DynamicUpdate=true \(Subdomains: _acme-challenge, staging\)/);

    // 5. TSIG Get Domain Permissions JSON
    const capGetDomainJson = createCapture();
    const codeGetDomainJson = await runCli(['--api-key', 'mock_token', 'tsig', 'domain', 'example.com', '--json'], capGetDomainJson);
    assert.equal(codeGetDomainJson, 0);
    const parsedDomainPerms = JSON.parse(capGetDomainJson.getStdout());
    assert.equal(parsedDomainPerms['primary-key'].allowAxfr, true);
    assert.deepEqual(parsedDomainPerms['primary-key'].subdomains, ['_acme-challenge', 'staging']);

    // 6. TSIG Set Permissions without subdomains
    const capPerm = createCapture();
    const codePerm = await runCli([
      '--api-key', 'mock_token',
      'tsig', 'set-permissions', 'example.com', 'primary-key',
      '--transfer', '--update',
    ], capPerm);
    assert.equal(codePerm, 0);
    assert.match(capPerm.getStdout(), /Updated TSIG permissions for domain 'example\.com' key 'primary-key': AXFR=true, DynamicUpdate=true/);
    assert.equal(lastPatchBody.allowAxfr, true);
    assert.equal(lastPatchBody.allowDnsUpdate, true);
    assert.equal(lastPatchBody.subdomains, undefined);

    // 7. TSIG Set Permissions with --subdomain
    const capPermSub = createCapture();
    const codePermSub = await runCli([
      '--api-key', 'mock_token',
      'tsig', 'set-permissions', 'example.com', 'primary-key',
      '--update',
      '--subdomain', '_acme_challenge',
      '-s', 'staging',
    ], capPermSub);
    assert.equal(codePermSub, 0);
    assert.match(capPermSub.getStdout(), /Subdomains=\[_acme_challenge, staging\]/);
    assert.deepEqual(lastPatchBody.subdomains, ['_acme_challenge', 'staging']);

    // 8. TSIG Set Permissions with comma-separated --subdomains and JSON output
    const capPermSubJson = createCapture();
    const codePermSubJson = await runCli([
      '--api-key', 'mock_token',
      'tsig', 'set-permissions', 'example.com', 'primary-key',
      '--subdomains', '_acme_challenge,staging',
      '--json',
    ], capPermSubJson);
    assert.equal(codePermSubJson, 0);
    const parsedSubJson = JSON.parse(capPermSubJson.getStdout());
    assert.equal(parsedSubJson.status, 'ok');
    assert.deepEqual(parsedSubJson.subdomains, ['_acme_challenge', 'staging']);

    // 9. TSIG Clear
    const capClear = createCapture();
    const codeClear = await runCli(['--api-key', 'mock_token', 'tsig', 'clear', 'example.com'], capClear);
    assert.equal(codeClear, 0);
    assert.match(capClear.getStdout(), /Cleared all TSIG keys for domain 'example\.com'/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('CLI handles AuthenticationError and API errors gracefully', async () => {
  const originalFetch = globalThis.fetch;
  const originalKey = process.env.ONLYDNS_API_KEY;
  const originalToken = process.env.ONLYDNS_API_TOKEN;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'onlydns-err-test-'));

  try {
    process.env.XDG_CONFIG_HOME = tempDir;
    delete process.env.ONLYDNS_API_KEY;
    delete process.env.ONLYDNS_API_TOKEN;

    // 1. Missing authentication token
    const capAuth = createCapture();
    const codeAuth = await runCli(['domains', 'list'], capAuth);
    assert.equal(codeAuth, 1);
    assert.match(capAuth.getStderr(), /Authentication Error/);

    // 2. 404 Not Found error from API
    globalThis.fetch = async () => ({
      status: 404,
      ok: false,
      text: async () => JSON.stringify({ title: 'Domain not found', description: ['The specified domain does not exist'] }),
      json: async () => ({ title: 'Domain not found', description: ['The specified domain does not exist'] }),
    });

    const cap404 = createCapture();
    const code404 = await runCli(['--api-key', 'test_key', 'records', 'list', 'nonexistent.com'], cap404);
    assert.equal(code404, 1);
    assert.match(cap404.getStderr(), /Not Found:.*Domain not found/);

    // 3. 400 Validation error from API
    globalThis.fetch = async () => ({
      status: 400,
      ok: false,
      text: async () => JSON.stringify({ title: 'Invalid Record', description: ['TTL must be greater than 0'] }),
      json: async () => ({ title: 'Invalid Record', description: ['TTL must be greater than 0'] }),
    });

    const cap400 = createCapture();
    const code400 = await runCli([
      '--api-key', 'test_key',
      'records', 'add', 'example.com',
      '-n', 'bad', '-t', 'A', '-v', '192.0.2.1',
    ], cap400);
    assert.equal(code400, 1);
    assert.match(cap400.getStderr(), /Validation Error:.*Invalid Record/);

    // 4. Unknown subcommand error
    const capUnknown = createCapture();
    const codeUnknown = await runCli(['foobar'], capUnknown);
    assert.equal(codeUnknown, 2);
    assert.match(capUnknown.getStderr(), /Unknown command 'foobar'/);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalKey !== undefined) process.env.ONLYDNS_API_KEY = originalKey;
    if (originalToken !== undefined) process.env.ONLYDNS_API_TOKEN = originalToken;
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
