/**
 * Command-line interface for OnlyDNS API (@onlydns/cli).
 *
 * Provides real-world testing capabilities and an intuitive interface for basic
 * domain, DNS record, DNSSEC, and TSIG management.
 */

import {
  OnlyDNSClient,
  OnlyDNSError,
  AuthenticationError,
  NotFoundError,
  ValidationError,
  APIError,
  DNSSECKeyAlgorithm,
  DNSSECKeyDigestType,
} from '@onlydns/sdk';
import type {
  DNSRecord,
  DNSSECStatus,
  TsigKey,
  DomainTsigPermissions,
  RecordType,
  TsigAlgorithm,
  User,
  APIToken,
  Scope,
} from '@onlydns/sdk';

import {
  clearConfig,
  getApiKey,
  getConfigFilePath,
  getStoredApiToken,
  loadConfig,
  setApiKey,
} from './config.js';

export interface CliOptions {
  apiKey?: string;
  baseUrl?: string;
  json?: boolean;
  timeout?: number;
  stdout?: (msg: string) => void;
  stderr?: (msg: string) => void;
}

export interface ParsedArgs {
  command?: string;
  action?: string;
  positionals: string[];
  options: Record<string, string | boolean | number | string[]>;
  apiKey?: string;
  baseUrl?: string;
  json: boolean;
  timeout: number;
  help: boolean;
  version: boolean;
}

const CLI_VERSION = '1.0.5';

function getOut(opts?: CliOptions): (msg: string) => void {
  return opts?.stdout || ((msg: string) => console.log(msg));
}

function getErr(opts?: CliOptions): (msg: string) => void {
  return opts?.stderr || ((msg: string) => console.error(msg));
}

export function createClient(args: ParsedArgs, opts?: CliOptions): OnlyDNSClient {
  const cfg = loadConfig();
  const apiToken = args.apiKey || opts?.apiKey || getApiKey();
  const baseUrl = args.baseUrl || opts?.baseUrl || cfg.base_url || OnlyDNSClient.DEFAULT_BASE_URL;
  const timeoutSec = args.timeout || opts?.timeout || 30.0;

  return new OnlyDNSClient({
    apiToken,
    baseUrl,
    timeout: timeoutSec * 1000,
  });
}

export function formatRecordsTable(records: DNSRecord[]): string {
  if (!records || records.length === 0) {
    return 'No records found.';
  }

  const header = `${'NAME'.padEnd(28)} ${'TYPE'.padEnd(8)} ${'TTL'.padEnd(8)} VALUES`;
  const separator = '-'.repeat(80);
  const lines = [header, separator];

  for (const rec of records) {
    const name = rec.name.padEnd(28);
    const rtype = String(rec.type).padEnd(8);
    const ttl = String(rec.ttl).padEnd(8);
    const valuesStr = Array.isArray(rec.records) ? rec.records.join(', ') : '';
    lines.push(`${name} ${rtype} ${ttl} ${valuesStr}`);
  }

  return lines.join('\n');
}

export function formatDnssecStatus(status: DNSSECStatus, domain: string): string {
  const lines: string[] = [];
  lines.push(`DNSSEC Status for ${domain}:`);
  lines.push(`  Enabled:     ${status.enabled}`);
  if (status.nsec3param) {
    lines.push(`  NSEC3 Param: ${status.nsec3param}`);
  }
  const keys = status.keys || [];
  lines.push(`  DS Keys (${keys.length}):`);
  keys.forEach((k, idx) => {
    const algStr = typeof k.algorithm === 'string' ? k.algorithm : DNSSECKeyAlgorithm[k.algorithm] || String(k.algorithm);
    const dtStr = typeof k.digestType === 'string' ? k.digestType : DNSSECKeyDigestType[k.digestType] || String(k.digestType);
    lines.push(`    [${idx + 1}] KeyTag: ${k.keyTag}, Algorithm: ${algStr}, DigestType: ${dtStr}`);
    lines.push(`        Digest: ${k.digest}`);
  });
  return lines.join('\n');
}

export function formatUsersTable(users: User[]): string {
  if (!users || users.length === 0) {
    return 'No users found.';
  }
  const header = `${'USER ID'.padEnd(20)} ${'USERNAME'.padEnd(28)} ${'SCOPES'.padEnd(24)} ${'ZONES'.padEnd(20)} STATUS`;
  const separator = '-'.repeat(105);
  const lines = [header, separator];
  for (const u of users) {
    const id = u.userId.padEnd(20);
    const username = u.userName.padEnd(28);
    const scopes = (u.scopes || []).join(',').slice(0, 22).padEnd(24);
    const zones = (u.allowedZones && u.allowedZones.length ? u.allowedZones.join(',') : '*').slice(0, 18).padEnd(20);
    const status = u.deactivatedAt ? 'Deactivated' : (u.locked ? 'Locked' : 'Active');
    lines.push(`${id} ${username} ${scopes} ${zones} ${status}`);
  }
  return lines.join('\n');
}

export function formatTokensTable(tokens: APIToken[]): string {
  if (!tokens || tokens.length === 0) {
    return 'No API tokens found.';
  }
  const header = `${'TOKEN ID'.padEnd(20)} ${'MASKED TOKEN'.padEnd(22)} ${'SCOPES'.padEnd(24)} ${'EXPIRES'.padEnd(14)} STATUS`;
  const separator = '-'.repeat(94);
  const lines = [header, separator];
  for (const t of tokens) {
    const id = t.tokenId.padEnd(20);
    const masked = (t.maskedToken || '-').padEnd(22);
    const scopes = (t.scopes || []).join(',').slice(0, 22).padEnd(24);
    const expires = t.expiresAt ? t.expiresAt.split('T')[0].padEnd(14) : 'Never'.padEnd(14);
    const status = t.deactivatedAt ? 'Revoked' : 'Active';
    lines.push(`${id} ${masked} ${scopes} ${expires} ${status}`);
  }
  return lines.join('\n');
}

export function formatTsigKeysList(keys: TsigKey[]): string {
  if (!keys || keys.length === 0) {
    return 'No TSIG keys found.';
  }
  const lines = [`TSIG Keys (${keys.length}):`];
  for (const k of keys) {
    lines.push(`  - ${k.name.padEnd(30)} (${k.algorithm})`);
  }
  return lines.join('\n');
}

export function formatDomainTsigPermissions(domain: string, perms: Record<string, DomainTsigPermissions>): string {
  const keys = Object.keys(perms);
  if (keys.length === 0) {
    return `No TSIG keys configured for domain '${domain}'.`;
  }
  const lines = [`TSIG Key Permissions for domain '${domain}':`];
  for (const k of keys) {
    const p = perms[k];
    const subStr = p.subdomains && p.subdomains.length > 0 ? ` (Subdomains: ${p.subdomains.join(', ')})` : '';
    lines.push(`  - ${k.padEnd(28)} AXFR=${p.allowAxfr}, DynamicUpdate=${p.allowDnsUpdate}${subStr}`);
  }
  return lines.join('\n');
}

// -----------------------------------------------------------------------------
// Subcommand Handlers
// -----------------------------------------------------------------------------

export async function cmdConfig(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action;

  if (action === 'set-key' || action === 'set-token' || action === 'login') {
    const key = (args.positionals[0] as string | undefined) || (args.options.key as string | undefined);
    if (!key || !key.trim()) {
      err('Error: API key is required. Usage: onlydns config set-key <KEY>');
      return 2;
    }
    const path = setApiKey(key, args.baseUrl);
    if (args.json) {
      out(JSON.stringify({ status: 'ok', message: 'API key saved', path }));
    } else {
      out(`API key successfully saved to ${path}`);
    }
    return 0;
  }

  if (action === 'get-key' || action === 'show') {
    const token = getStoredApiToken();
    const activeToken = getApiKey();
    if (args.json) {
      out(
        JSON.stringify({
          stored_key_present: Boolean(token),
          active_key_present: Boolean(activeToken),
          config_file: getConfigFilePath(),
        })
      );
    } else {
      if (activeToken) {
        const masked =
          activeToken.length >= 8
            ? activeToken.slice(0, 4) + '*'.repeat(Math.max(0, activeToken.length - 8)) + activeToken.slice(-4)
            : '***';
        out(`Active API key: ${masked}`);
        out(`Config path:    ${getConfigFilePath()}`);
      } else {
        out('No API key configured in environment or config file.');
      }
    }
    return 0;
  }

  if (action === 'path') {
    const p = getConfigFilePath();
    if (args.json) {
      out(JSON.stringify({ path: p }));
    } else {
      out(p);
    }
    return 0;
  }

  if (action === 'clear') {
    const cleared = clearConfig();
    if (args.json) {
      out(JSON.stringify({ status: cleared ? 'ok' : 'not_found', cleared }));
    } else {
      if (cleared) {
        out('Configuration file cleared.');
      } else {
        out('No configuration file found to clear.');
      }
    }
    return 0;
  }

  err('Error: Please specify a config action (set-key, get-key, path, clear). Usage: onlydns config <action>');
  return 2;
}

export async function cmdDomains(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action || 'list';
  const client = createClient(args, opts);

  if (action === 'create') {
    const domain = args.positionals[0] || (args.options.domain as string | undefined);
    if (!domain || !domain.trim()) {
      err('Error: Domain name is required. Usage: onlydns domains create <domain>');
      return 2;
    }
    await client.createDomain(domain.trim());
    if (args.json) {
      out(JSON.stringify({ status: 'ok', domain: domain.trim(), action: 'created' }));
    } else {
      out(`Successfully created domain '${domain.trim()}'.`);
    }
    return 0;
  }

  if (action === 'list') {
    const offset = Number(args.options.offset ?? 0) || 0;
    const limit = Number(args.options.limit ?? 200) || 200;
    const domains = await client.listDomains({ offset, limit });
    if (args.json) {
      out(JSON.stringify(domains, null, 2));
    } else {
      if (!domains || domains.length === 0) {
        out('No domains found.');
      } else {
        out(`Domains (${domains.length}):`);
        for (const d of domains) {
          out(`  - ${d}`);
        }
      }
    }
    return 0;
  }

  err(`Error: Unknown domains action '${action}'. Available actions: list, create`);
  return 2;
}

export async function cmdRecords(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action;

  if (!action) {
    err('Error: Please specify a records action (list, add, update, remove, find). Usage: onlydns records <action> <domain> [options]');
    return 2;
  }

  const domain = args.positionals[0] || (args.options.domain as string | undefined);
  if (!domain || !domain.trim()) {
    err(`Error: Domain name is required. Usage: onlydns records ${action} <domain> [options]`);
    return 2;
  }

  const client = createClient(args, opts);
  const cleanDomain = domain.trim();

  if (action === 'find') {
    const name = args.options.name as string | undefined;
    const rtype = (args.options.type as string | undefined) as RecordType | undefined;
    const valRaw = args.options.value;
    const val = Array.isArray(valRaw) ? valRaw[0] : (valRaw as string | undefined);

    if (!name && !rtype && !val) {
      err(
        "Error: At least one filter option (--name, --type, or --value) is required for 'find'. " +
        'Usage: onlydns records find <domain> [--name NAME] [--type TYPE] [--value VALUE]'
      );
      return 2;
    }

    const matches = await client.findRecords(cleanDomain, name, rtype, val);
    if (args.json) {
      out(JSON.stringify(matches, null, 2));
    } else {
      out(formatRecordsTable(matches));
    }
    return 0;
  }

  if (action === 'list') {
    const records = await client.getRecords(cleanDomain);
    if (args.json) {
      out(JSON.stringify(records, null, 2));
    } else {
      out(formatRecordsTable(records));
    }
    return 0;
  }

  if (action === 'add') {
    const name = args.options.name as string | undefined;
    const rtype = (args.options.type as string | undefined) as RecordType | undefined;
    if (!name || !rtype) {
      err('Error: Record --name (-n) and --type (-t) are required.');
      return 2;
    }

    const rawValues = Array.isArray(args.options.value)
      ? args.options.value
      : args.options.value
      ? [args.options.value as string]
      : [];

    const values: string[] = [];
    for (const v of rawValues) {
      for (const part of v.split(',')) {
        if (part.trim()) values.push(part.trim());
      }
    }

    if (values.length === 0) {
      err('Error: At least one --value (-v) must be provided.');
      return 2;
    }

    const ttl = args.options.ttl !== undefined ? Number(args.options.ttl) : undefined;
    await client.addRecord({
      domainName: cleanDomain,
      name,
      type: rtype,
      records: values,
      ttl,
    });

    if (args.json) {
      out(
        JSON.stringify(
          {
            status: 'ok',
            action: 'added',
            domain: cleanDomain,
            name,
            type: rtype,
            values,
            ttl,
          },
          null,
          2
        )
      );
    } else {
      const ttlStr = ttl !== undefined ? ` (TTL ${ttl})` : '';
      out(`Added record ${name} ${rtype} -> ${values.join(', ')}${ttlStr} in '${cleanDomain}'.`);
    }
    return 0;
  }

  if (action === 'update') {
    const name = args.options.name as string | undefined;
    const rtype = (args.options.type as string | undefined) as RecordType | undefined;
    if (!name || !rtype) {
      err('Error: Record --name (-n) and --type (-t) are required.');
      return 2;
    }

    const rawValues = Array.isArray(args.options.value)
      ? args.options.value
      : args.options.value
      ? [args.options.value as string]
      : [];

    const values: string[] = [];
    for (const v of rawValues) {
      for (const part of v.split(',')) {
        if (part.trim()) values.push(part.trim());
      }
    }

    if (values.length === 0) {
      err('Error: At least one --value (-v) must be provided for update.');
      return 2;
    }

    const ttl = args.options.ttl !== undefined ? Number(args.options.ttl) : undefined;
    await client.updateRecord(cleanDomain, name, rtype, values, ttl);

    if (args.json) {
      out(
        JSON.stringify(
          {
            status: 'ok',
            action: 'updated',
            domain: cleanDomain,
            name,
            type: rtype,
            values,
            ttl,
          },
          null,
          2
        )
      );
    } else {
      const ttlStr = ttl !== undefined ? ` (TTL ${ttl})` : '';
      out(`Updated record ${name} ${rtype} -> ${values.join(', ')}${ttlStr} in '${cleanDomain}'.`);
    }
    return 0;
  }

  if (action === 'remove') {
    const name = args.options.name as string | undefined;
    const rtype = (args.options.type as string | undefined) as RecordType | undefined;
    if (!name || !rtype) {
      err('Error: Record --name (-n) and --type (-t) are required.');
      return 2;
    }

    const rawValues = Array.isArray(args.options.value)
      ? args.options.value
      : args.options.value
      ? [args.options.value as string]
      : [];
    const targetValue = rawValues.length > 0 ? rawValues[0].trim() : undefined;

    await client.removeRecord({
      domainName: cleanDomain,
      name,
      type: rtype,
      value: targetValue,
    });

    if (args.json) {
      out(
        JSON.stringify(
          {
            status: 'ok',
            action: 'removed',
            domain: cleanDomain,
            name,
            type: rtype,
            value: targetValue,
          },
          null,
          2
        )
      );
    } else {
      if (targetValue) {
        out(`Removed value '${targetValue}' from ${name} ${rtype} in '${cleanDomain}'.`);
      } else {
        out(`Removed record ${name} ${rtype} from '${cleanDomain}'.`);
      }
    }
    return 0;
  }

  err(`Error: Unknown records action '${action}'. Available actions: list, add, update, remove, find`);
  return 2;
}

export async function cmdDnssec(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action;

  if (!action) {
    err('Error: Please specify a dnssec action (status, enable, disable). Usage: onlydns dnssec <action> <domain>');
    return 2;
  }

  const domain = args.positionals[0] || (args.options.domain as string | undefined);
  if (!domain || !domain.trim()) {
    err(`Error: Domain name is required. Usage: onlydns dnssec ${action} <domain>`);
    return 2;
  }

  const client = createClient(args, opts);
  const cleanDomain = domain.trim();

  if (action === 'status' || action === 'get') {
    const status = await client.getDnssecStatus(cleanDomain);
    if (args.json) {
      out(JSON.stringify(status, null, 2));
    } else {
      out(formatDnssecStatus(status, cleanDomain));
    }
    return 0;
  }

  if (action === 'enable') {
    await client.enableDnssec(cleanDomain);
    if (args.json) {
      out(JSON.stringify({ status: 'ok', domain: cleanDomain, dnssec: 'enabled' }));
    } else {
      out(`DNSSEC successfully enabled for '${cleanDomain}'.`);
    }
    return 0;
  }

  if (action === 'disable') {
    await client.disableDnssec(cleanDomain);
    if (args.json) {
      out(JSON.stringify({ status: 'ok', domain: cleanDomain, dnssec: 'disabled' }));
    } else {
      out(`DNSSEC successfully disabled for '${cleanDomain}'.`);
    }
    return 0;
  }

  err(`Error: Unknown dnssec action '${action}'. Available actions: status, enable, disable`);
  return 2;
}

export async function cmdTsig(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action;

  if (!action) {
    err('Error: Please specify a tsig action (list, create, get, set-permissions, clear). Usage: onlydns tsig <action> [options]');
    return 2;
  }

  const client = createClient(args, opts);

  if (action === 'list') {
    const keys = await client.getTsigKeys();
    if (args.json) {
      out(JSON.stringify(keys, null, 2));
    } else {
      out(formatTsigKeysList(keys));
    }
    return 0;
  }

  if (action === 'create') {
    const algoStr = (args.options.algo as string | undefined) || 'hmac-sha256';
    const res = await client.createTsigKey({
      algorithm: algoStr as TsigAlgorithm,
    });
    if (args.json) {
      out(JSON.stringify(res, null, 2));
    } else {
      out(`Created TSIG key '${res.name}':`);
      out(`  Algorithm: ${res.algorithm}`);
      out(`  Secret:    ${res.key}`);
    }
    return 0;
  }

  if (action === 'get') {
    const keyName = args.positionals[0] || (args.options.keyName as string | undefined);
    if (!keyName || !keyName.trim()) {
      err('Error: TSIG key name is required. Usage: onlydns tsig get <key_name>');
      return 2;
    }
    const key = await client.getTsigKey(keyName.trim());
    if (args.json) {
      out(JSON.stringify(key, null, 2));
    } else {
      out(`TSIG Key '${key.name}':`);
      out(`  Algorithm: ${key.algorithm}`);
      if (key.key) {
        out(`  Secret:    ${key.key}`);
      }
    }
    return 0;
  }

  if (action === 'get-domain' || action === 'domain') {
    const domain = args.positionals[0] || (args.options.domain as string | undefined);
    if (!domain || !domain.trim()) {
      err('Error: Domain name is required. Usage: onlydns tsig get-domain <domain>');
      return 2;
    }
    const perms = await client.getDomainTsig(domain.trim());
    if (args.json) {
      out(JSON.stringify(perms, null, 2));
    } else {
      out(formatDomainTsigPermissions(domain.trim(), perms));
    }
    return 0;
  }

  if (action === 'set-permissions') {
    const domain = args.positionals[0] || (args.options.domain as string | undefined);
    const keyName = args.positionals[1] || (args.options.keyName as string | undefined);
    if (!domain || !domain.trim() || !keyName || !keyName.trim()) {
      err('Error: Domain name and TSIG key name are required. Usage: onlydns tsig set-permissions <domain> <key_name> [--transfer] [--update] [--subdomain SUBDOMAIN]');
      return 2;
    }

    const rawSubdomains = Array.isArray(args.options.subdomain)
      ? args.options.subdomain
      : args.options.subdomain
      ? [args.options.subdomain as string]
      : [];

    const subdomains: string[] = [];
    for (const s of rawSubdomains) {
      for (const part of s.split(',')) {
        if (part.trim()) subdomains.push(part.trim());
      }
    }

    const transfer = Boolean(args.options.transfer || args.options.axfr);
    const update = Boolean(args.options.update || subdomains.length > 0);

    await client.updateDomainTsig(
      domain.trim(),
      keyName.trim(),
      transfer,
      update,
      subdomains.length > 0 ? subdomains : undefined
    );

    const payload: Record<string, unknown> = {
      status: 'ok',
      domain: domain.trim(),
      key_name: keyName.trim(),
      allow_axfr: transfer,
      allow_dns_update: update,
    };
    if (subdomains.length > 0) {
      payload.subdomains = subdomains;
    }

    if (args.json) {
      out(JSON.stringify(payload, null, 2));
    } else {
      const subMsg = subdomains.length > 0 ? `, Subdomains=[${subdomains.join(', ')}]` : '';
      out(`Updated TSIG permissions for domain '${domain.trim()}' key '${keyName.trim()}': AXFR=${transfer}, DynamicUpdate=${update}${subMsg}.`);
    }
    return 0;
  }

  if (action === 'clear') {
    const domain = args.positionals[0] || (args.options.domain as string | undefined);
    if (!domain || !domain.trim()) {
      err('Error: Domain name is required. Usage: onlydns tsig clear <domain>');
      return 2;
    }
    await client.deleteDomainTsig(domain.trim());
    if (args.json) {
      out(JSON.stringify({ status: 'ok', domain: domain.trim(), action: 'tsig_cleared' }));
    } else {
      out(`Cleared all TSIG keys for domain '${domain.trim()}'.`);
    }
    return 0;
  }

  err(`Error: Unknown tsig action '${action}'. Available actions: list, create, get, get-domain, set-permissions, clear`);
  return 2;
}

export async function cmdUsers(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action;

  if (!action) {
    err('Error: Please specify a users action (list, get, invite, delete). Usage: onlydns users <action> [options]');
    return 2;
  }

  const client = createClient(args, opts);

  if (action === 'list') {
    const users = await client.listUsers();
    if (args.json) {
      out(JSON.stringify(users, null, 2));
    } else {
      out(formatUsersTable(users));
    }
    return 0;
  }

  if (action === 'get') {
    const userId = args.positionals[0] || (args.options.userId as string | undefined);
    if (!userId || !userId.trim()) {
      err('Error: User ID is required. Usage: onlydns users get <userId>');
      return 2;
    }
    const user = await client.getUser(userId.trim());
    if (args.json) {
      out(JSON.stringify(user, null, 2));
    } else {
      out(`User: ${user.userName} (${user.userId})`);
      out(`  Name:        ${[user.firstName, user.lastName].filter(Boolean).join(' ') || 'N/A'}`);
      out(`  Phone:       ${user.phone && user.phone !== '0' ? user.phone : 'Not provided'}`);
      out(`  Scopes:      ${(user.scopes || []).join(', ')}`);
      out(`  Zones:       ${user.allowedZones && user.allowedZones.length ? user.allowedZones.join(', ') : 'All Zones (*)'}`);
      out(`  Status:      ${user.deactivatedAt ? 'Deactivated' : (user.locked ? 'Locked' : 'Active')}`);
    }
    return 0;
  }

  if (action === 'invite' || action === 'create') {
    const email = args.positionals[0] || (args.options.email as string | undefined);
    if (!email || !email.trim()) {
      err('Error: Email address is required. Usage: onlydns users invite <email> [--scopes SCOPES] [--zones ZONES] [--phone PHONE]');
      return 2;
    }
    const scopesRaw = (args.options.scopes as string | undefined) || 'admin';
    const scopes = scopesRaw.split(',').map((s) => s.trim()).filter(Boolean);
    const zonesRaw = args.options.zones as string | undefined;
    const allowedZones = zonesRaw ? zonesRaw.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
    const phone = (args.options.phone as string | undefined) || undefined;

    const user = await client.createUser({
      email: email.trim(),
      scopes,
      allowed_zones: allowedZones,
      phone,
    });
    if (args.json) {
      out(JSON.stringify(user, null, 2));
    } else {
      out(`User '${user.userName}' successfully invited (ID: ${user.userId}).`);
    }
    return 0;
  }

  if (action === 'delete' || action === 'deactivate') {
    const userId = args.positionals[0] || (args.options.userId as string | undefined);
    if (!userId || !userId.trim()) {
      err('Error: User ID is required. Usage: onlydns users delete <userId>');
      return 2;
    }
    await client.deleteUser(userId.trim());
    if (args.json) {
      out(JSON.stringify({ status: 'ok', userId: userId.trim(), action: 'deactivated' }));
    } else {
      out(`User '${userId.trim()}' successfully deactivated.`);
    }
    return 0;
  }

  err(`Error: Unknown users action '${action}'. Available actions: list, get, invite, delete`);
  return 2;
}

export async function cmdAccount(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action || 'get';
  const client = createClient(args, opts);

  if (action === 'get' || action === 'info' || action === 'show') {
    const info = await client.getAccount();
    if (args.json) {
      out(JSON.stringify(info, null, 2));
    } else {
      out('Account Details:');
      out(`  Account ID:   ${info.accountId}`);
      if (info.companyName) {
        out(`  Company:      ${info.companyName}`);
      }
      if (info.firstName || info.lastName) {
        out(`  Contact Name: ${((info.firstName || '') + ' ' + (info.lastName || '')).trim()}`);
      }
      if (info.address) {
        const addr = info.address;
        const parts = [addr.street1, addr.street2, addr.city, addr.state, addr.postalCode, addr.countryId].filter(Boolean);
        out(`  Address:      ${parts.join(', ')}`);
      }
      if (info.package) {
        const pkg = info.package;
        out(`  Package:      ${pkg.description} ($${Number(pkg.amount).toFixed(2)}/mo)`);
        const feats = pkg.features;
        out(`  Features:     Domains=${feats.domains}, Records=${feats.records}, Queries=${feats.queries}`);
        out(`                DNSSEC=${feats.dnssec}, TSIG=${feats.tsig}, Proxy=${feats.proxy}, CustomSSO=${feats.customSSO}`);
      }
    }
    return 0;
  }

  if (action === 'metrics' || action === 'usage') {
    const metrics = await client.getAccountMetrics();
    if (args.json) {
      out(JSON.stringify(metrics, null, 2));
    } else {
      out('Account Resource Usage & Entitlements:');
      out(`  Account ID:             ${metrics.accountId}`);
      if (metrics.package) {
        out(`  Active Package:         ${metrics.package.description} (${metrics.package.id})`);
      }
      out('');
      const u = metrics.usage;
      const fmtLimit = (limit: number) => (limit === -1 ? 'Unlimited' : (limit === 0 ? '0 (Not allowed)' : String(limit)));
      out('  Resource                Current Usage                  Plan Limit');
      out('  -----------------------------------------------------------------');
      out(`  Domains                 ${String(u.domains.current).padEnd(30)} ${fmtLimit(u.domains.limit)}`);

      const recs = u.records;
      const recsDisplay = recs.maxZoneRecords !== undefined
        ? `${recs.maxZoneRecords} peak (${recs.totalRecords} total${recs.maxZoneName ? ` - ${recs.maxZoneName}` : ''})`
        : String(recs.current ?? 0);
      const recsLimit = recs.limitPerZone !== undefined
        ? `${fmtLimit(recs.limitPerZone)} / zone`
        : fmtLimit(recs.limit ?? 0);
      out(`  DNS Records             ${recsDisplay.padEnd(30)} ${recsLimit}`);

      out(`  Monthly Queries         ${String(u.queries.current).padEnd(30)} ${fmtLimit(u.queries.limit)}`);
      out(`  DNSSEC-Signed Zones     ${String(u.dnssec.current).padEnd(30)} ${u.dnssec.enabled ? 'Enabled' : 'Disabled'}`);
      out(`  TSIG Keys               ${String(u.tsigKeys.current).padEnd(30)} ${fmtLimit(u.tsigKeys.limit)}`);
      out(`  24h API Changes         ${String(u.changesLast24Hours.current).padEnd(30)} ${fmtLimit(u.changesLast24Hours.limit)}`);
      const rpmDisplay = u.apiRequestsPerMinute.averageLast24Hours !== undefined
        ? `${u.apiRequestsPerMinute.current} (24h avg: ${u.apiRequestsPerMinute.averageLast24Hours})`
        : String(u.apiRequestsPerMinute.current);
      out(`  API Requests / Min      ${rpmDisplay.padEnd(30)} ${fmtLimit(u.apiRequestsPerMinute.limit)}`);
      out(`  Active API Tokens       ${String(u.apiTokens.current).padEnd(30)} ${fmtLimit(u.apiTokens.limit)}`);
    }
    return 0;
  }

  if (action === 'billing') {
    const billing = await client.getAccountBilling();
    if (args.json) {
      out(JSON.stringify(billing, null, 2));
    } else {
      out('Account Billing Status:');
      out(`  Account ID:             ${billing.accountId}`);
      out(`  Amount Due:             $${billing.amountDue?.value || '0.00'} ${billing.currency}`);
      out(`  Past Due Amount:        $${billing.pastDueAmount?.value || '0.00'} ${billing.currency}`);
      out(`  Past Due:               ${billing.pastDue}`);
      out(`  Suspended:              ${billing.suspended}`);
      out(`  Suspended (Non-Payment):${billing.suspendedForNonPayment}`);
      if (billing.billingAssessedTo) {
        out(`  Assessed Through:       ${billing.billingAssessedTo}`);
      }
    }
    return 0;
  }

  if (action === 'oidc') {
    const oidcAction = args.positionals[0] || 'get';

    if (oidcAction === 'get' || oidcAction === 'show') {
      const cfg = await client.getAccountOidc();
      if (args.json) {
        out(JSON.stringify(cfg, null, 2));
      } else {
        out('Custom OIDC SSO Configuration:');
        out(`  Configured:     ${cfg.configured}`);
        if (cfg.configured) {
          out(`  Discovery URL:  ${cfg.discoveryUrl}`);
          out(`  Client ID:      ${cfg.clientId}`);
          if (cfg.clientSecretMasked) {
            out(`  Client Secret:  ${cfg.clientSecretMasked}`);
          }
          out(`  Enforce SSO:    ${cfg.enforceSso}`);
          out(`  Admins Count:   ${cfg.breakGlassAdminsCount}`);
          if (cfg.nonCompliantUsers && cfg.nonCompliantUsers.length > 0) {
            out(`  Non-Compliant:  ${cfg.nonCompliantUsers.length} users`);
            for (const u of cfg.nonCompliantUsers) {
              out(`    - ${u.userName} (${u.userId}): ${u.reason}`);
            }
          }
        }
      }
      return 0;
    }

    if (oidcAction === 'set' || oidcAction === 'save' || oidcAction === 'update') {
      const discoveryUrl = (args.options['discovery-url'] || args.options.discoveryUrl) as string | undefined;
      const clientId = (args.options['client-id'] || args.options.clientId) as string | undefined;
      const clientSecret = (args.options['client-secret'] || args.options.clientSecret) as string | undefined;
      const enforceSso = args.options['enforce-sso'] !== undefined
        ? Boolean(args.options['enforce-sso'])
        : (args.options.enforceSso !== undefined ? Boolean(args.options.enforceSso) : undefined);

      const cfg = await client.saveAccountOidc({
        discoveryUrl,
        clientId,
        clientSecret,
        enforceSso,
      });

      if (args.json) {
        out(JSON.stringify(cfg, null, 2));
      } else {
        out('Custom OIDC SSO configuration saved successfully.');
        out(`  Discovery URL:  ${cfg.discoveryUrl}`);
        out(`  Client ID:      ${cfg.clientId}`);
        out(`  Enforce SSO:    ${cfg.enforceSso}`);
      }
      return 0;
    }

    if (oidcAction === 'delete' || oidcAction === 'remove' || oidcAction === 'clear') {
      const res = await client.deleteAccountOidc();
      if (args.json) {
        out(JSON.stringify(res, null, 2));
      } else {
        out('Custom OIDC SSO configuration removed successfully.');
      }
      return 0;
    }

    if (oidcAction === 'test') {
      const discoveryUrl = (args.options['discovery-url'] || args.options.discoveryUrl || args.positionals[1]) as string | undefined;
      const clientId = (args.options['client-id'] || args.options.clientId) as string | undefined;
      const clientSecret = (args.options['client-secret'] || args.options.clientSecret) as string | undefined;
      const testOpts: { discoveryUrl?: string; clientId?: string; clientSecret?: string } = {};
      if (discoveryUrl) testOpts.discoveryUrl = discoveryUrl;
      if (clientId) testOpts.clientId = clientId;
      if (clientSecret) testOpts.clientSecret = clientSecret;

      const res = await client.testAccountOidc(Object.keys(testOpts).length ? testOpts : undefined);
      if (args.json) {
        out(JSON.stringify(res, null, 2));
      } else {
        if (res.success) {
          out('OIDC SSO discovery endpoint test successful.');
          if (res.issuer) {
            out(`  Issuer:         ${res.issuer}`);
          }
          if (res.authorizationEndpoint) {
            out(`  Auth Endpoint:  ${res.authorizationEndpoint}`);
          }
          if (res.tokenEndpoint) {
            out(`  Token Endpoint: ${res.tokenEndpoint}`);
          }
          if (res.clientCredentialsTested) {
            const status = res.clientCredentialsValid ? 'Validated' : 'Failed';
            out(`  Client Creds:   ${status}`);
          }
        } else {
          out('OIDC SSO discovery endpoint test failed.');
        }
      }
      return 0;
    }

    err(`Error: Unknown oidc action '${oidcAction}'. Available actions: get, set, delete, test`);
    return 2;
  }

  err(`Error: Unknown account action '${action}'. Available actions: get, oidc`);
  return 2;
}

export async function cmdTokens(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const action = args.action;

  if (!action) {
    err('Error: Please specify a tokens action (list, get, create, delete). Usage: onlydns tokens <action> [options]');
    return 2;
  }

  const client = createClient(args, opts);

  if (action === 'list') {
    const tokens = await client.listTokens();
    if (args.json) {
      out(JSON.stringify(tokens, null, 2));
    } else {
      out(formatTokensTable(tokens));
    }
    return 0;
  }

  if (action === 'get') {
    const tokenId = args.positionals[0] || (args.options.tokenId as string | undefined);
    if (!tokenId || !tokenId.trim()) {
      err('Error: Token ID is required. Usage: onlydns tokens get <tokenId>');
      return 2;
    }
    const token = await client.getToken(tokenId.trim());
    if (args.json) {
      out(JSON.stringify(token, null, 2));
    } else {
      out(`Token: ${token.maskedToken || token.tokenId} (${token.tokenId})`);
      out(`  Scopes:   ${(token.scopes || []).join(', ')}`);
      out(`  Zones:    ${token.allowedZones && token.allowedZones.length ? token.allowedZones.join(', ') : 'All Zones (*)'}`);
      out(`  Networks: ${token.allowedNetwork && token.allowedNetwork.length ? token.allowedNetwork.join(', ') : '0.0.0.0/0 (Any)'}`);
      out(`  Expires:  ${token.expiresAt || 'Never'}`);
    }
    return 0;
  }

  if (action === 'create') {
    const scopesRaw = (args.options.scopes as string | undefined) || 'records:write';
    const scopes = scopesRaw.split(',').map((s) => s.trim()).filter(Boolean);
    const zonesRaw = args.options.zones as string | undefined;
    const allowedZones = zonesRaw ? zonesRaw.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
    const networkRaw = args.options.network as string | undefined;
    const allowedNetwork = networkRaw ? networkRaw.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
    const expires = args.options.expires as string | undefined;

    const token = await client.createToken({
      scopes,
      allowed_zones: allowedZones,
      allowed_network: allowedNetwork,
      expires_at: expires,
    });
    if (args.json) {
      out(JSON.stringify(token, null, 2));
    } else {
      out(`API Key Created Successfully:`);
      out(`  Token:    ${token.token || token.authorization || ''}`);
      out(`  Scopes:   ${(token.scopes || []).join(', ')}`);
      out(`  Expires:  ${token.expiresAt || 'Never'}`);
      out(`  Notice:   Copy this token now; full secret will not be displayed again.`);
    }
    return 0;
  }

  if (action === 'delete' || action === 'revoke') {
    const tokenId = args.positionals[0] || (args.options.tokenId as string | undefined);
    if (!tokenId || !tokenId.trim()) {
      err('Error: Token ID is required. Usage: onlydns tokens delete <tokenId>');
      return 2;
    }
    await client.deleteToken(tokenId.trim());
    if (args.json) {
      out(JSON.stringify({ status: 'ok', tokenId: tokenId.trim(), action: 'revoked' }));
    } else {
      out(`API Key '${tokenId.trim()}' successfully revoked.`);
    }
    return 0;
  }

  err(`Error: Unknown tokens action '${action}'. Available actions: list, get, create, delete`);
  return 2;
}

export async function cmdLogin(args: ParsedArgs, opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);
  const username = args.positionals[0] || (args.options.username as string | undefined);
  const password = args.positionals[1] || (args.options.password as string | undefined);

  if (!username || !username.trim() || !password || !password.trim()) {
    err('Error: Username and password are required. Usage: onlydns login <username> <password>');
    return 2;
  }

  const baseUrl = args.baseUrl || opts?.baseUrl || OnlyDNSClient.DEFAULT_BASE_URL;
  const res = await OnlyDNSClient.login({
    username: username.trim(),
    password: password.trim(),
  }, { baseUrl });

  setApiKey(res.token);

  if (args.json) {
    out(JSON.stringify({ status: 'ok', user: res.user, token_type: res.token_type, expires_in: res.expires_in }, null, 2));
  } else {
    out(`Successfully authenticated as '${res.user.userName}'. Saved JWT bearer token to configuration.`);
  }
  return 0;
}

// -----------------------------------------------------------------------------
// Argument Parsing & Help
// -----------------------------------------------------------------------------

export function parseArgs(rawArgs: string[]): ParsedArgs {
  const result: ParsedArgs = {
    positionals: [],
    options: {},
    json: false,
    timeout: 30.0,
    help: false,
    version: false,
  };

  let i = 0;
  while (i < rawArgs.length) {
    const arg = rawArgs[i];

    if (arg === '--help' || arg === '-h') {
      result.help = true;
      i++;
      continue;
    }

    if (arg === '--version' || arg === '-V') {
      result.version = true;
      i++;
      continue;
    }

    if (arg === '--json') {
      result.json = true;
      i++;
      continue;
    }

    if (arg === '--api-key' || arg === '-k') {
      result.apiKey = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--api-key=')) {
      result.apiKey = arg.slice('--api-key='.length);
      i++;
      continue;
    }

    if (arg === '--base-url') {
      result.baseUrl = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--base-url=')) {
      result.baseUrl = arg.slice('--base-url='.length);
      i++;
      continue;
    }

    if (arg === '--timeout') {
      result.timeout = parseFloat(rawArgs[i + 1]) || 30.0;
      i += 2;
      continue;
    }
    if (arg.startsWith('--timeout=')) {
      result.timeout = parseFloat(arg.slice('--timeout='.length)) || 30.0;
      i++;
      continue;
    }

    // Flag options with values
    if (arg === '--name' || arg === '-n') {
      result.options.name = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--name=')) {
      result.options.name = arg.slice('--name='.length);
      i++;
      continue;
    }

    if (arg === '--type' || arg === '-t') {
      result.options.type = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--type=')) {
      result.options.type = arg.slice('--type='.length);
      i++;
      continue;
    }

    if (arg === '--value' || arg === '-v') {
      const val = rawArgs[i + 1];
      if (!result.options.value) {
        result.options.value = [val];
      } else if (Array.isArray(result.options.value)) {
        result.options.value.push(val);
      } else {
        result.options.value = [result.options.value as string, val];
      }
      i += 2;
      continue;
    }
    if (arg.startsWith('--value=')) {
      const val = arg.slice('--value='.length);
      if (!result.options.value) {
        result.options.value = [val];
      } else if (Array.isArray(result.options.value)) {
        result.options.value.push(val);
      } else {
        result.options.value = [result.options.value as string, val];
      }
      i++;
      continue;
    }

    if (arg === '--ttl') {
      result.options.ttl = parseInt(rawArgs[i + 1], 10);
      i += 2;
      continue;
    }
    if (arg.startsWith('--ttl=')) {
      result.options.ttl = parseInt(arg.slice('--ttl='.length), 10);
      i++;
      continue;
    }

    if (arg === '--algo' || arg === '-a') {
      result.options.algo = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--algo=')) {
      result.options.algo = arg.slice('--algo='.length);
      i++;
      continue;
    }

    if (arg === '--offset') {
      result.options.offset = parseInt(rawArgs[i + 1], 10);
      i += 2;
      continue;
    }
    if (arg === '--limit') {
      result.options.limit = parseInt(rawArgs[i + 1], 10);
      i += 2;
      continue;
    }

    if (arg === '--transfer' || arg === '--axfr') {
      result.options.transfer = true;
      i++;
      continue;
    }

    if (arg === '--update') {
      result.options.update = true;
      i++;
      continue;
    }

    if (arg === '--subdomain' || arg === '--subdomains' || arg === '-s') {
      const val = rawArgs[i + 1];
      if (!result.options.subdomain) {
        result.options.subdomain = [val];
      } else if (Array.isArray(result.options.subdomain)) {
        result.options.subdomain.push(val);
      } else {
        result.options.subdomain = [result.options.subdomain as string, val];
      }
      i += 2;
      continue;
    }
    if (arg.startsWith('--subdomain=') || arg.startsWith('--subdomains=')) {
      const prefix = arg.startsWith('--subdomain=') ? '--subdomain=' : '--subdomains=';
      const val = arg.slice(prefix.length);
      if (!result.options.subdomain) {
        result.options.subdomain = [val];
      } else if (Array.isArray(result.options.subdomain)) {
        result.options.subdomain.push(val);
      } else {
        result.options.subdomain = [result.options.subdomain as string, val];
      }
      i++;
      continue;
    }
    if (arg.startsWith('-s=')) {
      const val = arg.slice('-s='.length);
      if (!result.options.subdomain) {
        result.options.subdomain = [val];
      } else if (Array.isArray(result.options.subdomain)) {
        result.options.subdomain.push(val);
      } else {
        result.options.subdomain = [result.options.subdomain as string, val];
      }
      i++;
      continue;
    }

    if (arg === '--scopes' || arg === '--scope') {
      result.options.scopes = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--scopes=') || arg.startsWith('--scope=')) {
      result.options.scopes = arg.split('=')[1];
      i++;
      continue;
    }

    if (arg === '--zones' || arg === '--zone') {
      result.options.zones = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--zones=') || arg.startsWith('--zone=')) {
      result.options.zones = arg.split('=')[1];
      i++;
      continue;
    }

    if (arg === '--expires' || arg === '--expires-at' || arg === '--exp') {
      result.options.expires = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--expires=') || arg.startsWith('--expires-at=') || arg.startsWith('--exp=')) {
      result.options.expires = arg.split('=')[1];
      i++;
      continue;
    }

    if (arg === '--network' || arg === '--ip') {
      result.options.network = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--network=') || arg.startsWith('--ip=')) {
      result.options.network = arg.split('=')[1];
      i++;
      continue;
    }

    if (arg === '--phone' || arg === '--phone-number') {
      result.options.phone = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--phone=') || arg.startsWith('--phone-number=')) {
      result.options.phone = arg.split('=')[1];
      i++;
      continue;
    }

    if (arg === '--username' || arg === '-u') {
      result.options.username = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--username=') || arg.startsWith('-u=')) {
      result.options.username = arg.split('=')[1];
      i++;
      continue;
    }

    if (arg === '--password' || arg === '-p') {
      result.options.password = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--password=') || arg.startsWith('-p=')) {
      result.options.password = arg.split('=')[1];
      i++;
      continue;
    }

    if (arg === '--discovery-url' || arg === '--url') {
      result.options['discovery-url'] = rawArgs[i + 1];
      result.options.discoveryUrl = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--discovery-url=') || arg.startsWith('--url=')) {
      const val = arg.split('=')[1];
      result.options['discovery-url'] = val;
      result.options.discoveryUrl = val;
      i++;
      continue;
    }

    if (arg === '--client-id') {
      result.options['client-id'] = rawArgs[i + 1];
      result.options.clientId = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--client-id=')) {
      const val = arg.split('=')[1];
      result.options['client-id'] = val;
      result.options.clientId = val;
      i++;
      continue;
    }

    if (arg === '--client-secret') {
      result.options['client-secret'] = rawArgs[i + 1];
      result.options.clientSecret = rawArgs[i + 1];
      i += 2;
      continue;
    }
    if (arg.startsWith('--client-secret=')) {
      const val = arg.split('=')[1];
      result.options['client-secret'] = val;
      result.options.clientSecret = val;
      i++;
      continue;
    }

    if (arg === '--enforce-sso' || arg === '--enforce') {
      result.options['enforce-sso'] = true;
      result.options.enforceSso = true;
      i++;
      continue;
    }
    if (arg === '--no-enforce-sso' || arg === '--no-enforce') {
      result.options['enforce-sso'] = false;
      result.options.enforceSso = false;
      i++;
      continue;
    }

    // Positional arguments
    if (!result.command) {
      result.command = arg;
    } else if (!result.action && ['domains', 'records', 'dnssec', 'tsig', 'config', 'users', 'tokens', 'account'].includes(result.command)) {
      result.action = arg;
    } else {
      result.positionals.push(arg);
    }

    i++;
  }

  return result;
}

export function showHelp(command?: string): string {
  if (command === 'domains') {
    return `usage: onlydns domains [-h] {list,create} ...

Domain management commands

commands:
  list                List all domain names in the account
  create              Create a new domain zone (e.g. onlydns domains create example.com)
`;
  }

  if (command === 'records') {
    return `usage: onlydns records [-h] {list,add,update,remove,find} ...

DNS record management commands

commands:
  list                List all DNS records for a domain
  find                Find DNS records matching name, type, and/or value filters
  add                 Add or append values to a DNS record
  update              Replace/update all values and TTL of a DNS record
  remove              Remove an entire DNS record or a specific value from it
`;
  }

  if (command === 'dnssec') {
    return `usage: onlydns dnssec [-h] {status,enable,disable} ...

DNSSEC lifecycle management commands

commands:
  status (get)        Get DNSSEC status and DS keys for a domain
  enable              Enable DNSSEC signing for a domain
  disable             Disable DNSSEC signing for a domain
`;
  }

  if (command === 'tsig') {
    return `usage: onlydns tsig [-h] {list,create,get,get-domain,set-permissions,clear} ...

TSIG key management commands

commands:
  list                List all TSIG keys in the account
  create              Generate a new TSIG key
  get                 Get details of a specific TSIG key
  get-domain (domain) Get TSIG key permissions configured for a domain
  set-permissions     Configure TSIG key permissions for a domain (with optional --subdomain restrictions)
  clear               Remove all TSIG key permissions for a domain
`;
  }

  if (command === 'config') {
    return `usage: onlydns config [-h] {set-key,get-key,path,clear} ...

Configuration and credential management commands

commands:
  set-key (login)     Save API key to ~/.config/onlydns/config.json
  get-key (show)      Show active API key status and config file path
  path                Print configuration file path
  clear               Delete stored configuration file
`;
  }

  if (command === 'users') {
    return `usage: onlydns users [-h] {list,get,invite,delete} ...

Portal user management commands

commands:
  list                List all users in the account
  get <userId>        Get user details and assigned permissions
  invite <email>      Invite a new portal user (--scopes, --zones)
  delete <userId>     Deactivate a portal user
`;
  }

  if (command === 'tokens') {
    return `usage: onlydns tokens [-h] {list,get,create,delete} ...

API token management commands

commands:
  list                List all API access tokens
  get <tokenId>       Get token details and metadata
  create              Generate a new API token (--scopes, --zones, --expires, --network)
  delete <tokenId>    Revoke/deactivate an API token
`;
  }

  if (command === 'account') {
    return `usage: onlydns account [-h] {get,metrics,billing,oidc} ...

Account details, metrics, billing, and custom OIDC SSO commands

commands:
  get (info, show)    Get account metadata, contact details, and billing package feature entitlements
  metrics (usage)     Get real-time resource usage statistics and plan limits
  billing             Get account billing balance and suspension status
  oidc                Manage custom OIDC SSO settings (get, set, delete, test)
`;
  }

  if (command === 'login') {
    return `usage: onlydns login <username> <password>

Authenticate with user credentials and save a short-lived JWT token.
`;
  }

  return `usage: onlydns [-h] [--api-key API_KEY] [--base-url BASE_URL] [--json] [--timeout TIMEOUT] [--version]
               {domains,records,dnssec,tsig,users,tokens,account,login,config} ...

Command-line interface for OnlyDNS API (onlydns.com).

options:
  -h, --help            show this help message and exit
  --api-key, -k API_KEY OnlyDNS API bearer token (overrides environment variable and stored config)
  --base-url BASE_URL   Custom base API URL (default: https://api.onlydns.com/v1)
  --json                Output results in JSON format
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 30.0)
  --version, -V         show program's version number and exit

commands:
  domains               Domain management (list, create)
  records               DNS record management (list, add, update, remove, find)
  dnssec                DNSSEC management (status, enable, disable)
  tsig                  TSIG key management (list, create, get, set-permissions, clear)
  users                 Portal user management (list, get, invite, delete)
  tokens                API token management (list, get, create, delete)
  account               Account details, metrics, billing, and custom OIDC SSO management (get, metrics, billing, oidc)
  login                 Interactive user authentication
  config                Configuration and authentication (set-key, get-key, path, clear)
`;
}

// -----------------------------------------------------------------------------
// Main Entrypoint
// -----------------------------------------------------------------------------

export async function runCli(argv: string[], opts?: CliOptions): Promise<number> {
  const out = getOut(opts);
  const err = getErr(opts);

  try {
    const args = parseArgs(argv);

    if (args.version) {
      out(`@onlydns/cli ${CLI_VERSION}`);
      return 0;
    }

    if (args.help || !args.command) {
      out(showHelp(args.command));
      return 0;
    }

    switch (args.command) {
      case 'domains':
        return await cmdDomains(args, opts);
      case 'records':
        return await cmdRecords(args, opts);
      case 'dnssec':
        return await cmdDnssec(args, opts);
      case 'tsig':
        return await cmdTsig(args, opts);
      case 'users':
        return await cmdUsers(args, opts);
      case 'tokens':
        return await cmdTokens(args, opts);
      case 'account':
        return await cmdAccount(args, opts);
      case 'login':
        return await cmdLogin(args, opts);
      case 'config':
        return await cmdConfig(args, opts);
      default:
        err(`Error: Unknown command '${args.command}'. Available commands: domains, records, dnssec, tsig, users, tokens, account, login, config`);
        out(showHelp());
        return 2;
    }
  } catch (error: unknown) {
    if (error instanceof AuthenticationError) {
      err(`Authentication Error: ${error.message}`);
      return 1;
    }
    if (error instanceof NotFoundError) {
      err(`Not Found: ${error.message}`);
      return 1;
    }
    if (error instanceof ValidationError) {
      err(`Validation Error: ${error.message}`);
      return 1;
    }
    if (error instanceof APIError) {
      err(`API Error (${error.statusCode}): ${error.message}`);
      return 1;
    }
    if (error instanceof OnlyDNSError) {
      err(`OnlyDNS Error: ${error.message}`);
      return 1;
    }
    if (error instanceof Error) {
      err(`Unexpected Error: ${error.message}`);
      return 1;
    }
    err(`Unexpected Error: ${String(error)}`);
    return 1;
  }
}
