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

const CLI_VERSION = '1.0.4';

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

    // Positional arguments
    if (!result.command) {
      result.command = arg;
    } else if (!result.action && ['domains', 'records', 'dnssec', 'tsig', 'config'].includes(result.command)) {
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

  return `usage: onlydns [-h] [--api-key API_KEY] [--base-url BASE_URL] [--json] [--timeout TIMEOUT] [--version]
               {domains,records,dnssec,tsig,config} ...

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
      case 'config':
        return await cmdConfig(args, opts);
      default:
        err(`Error: Unknown command '${args.command}'. Available commands: domains, records, dnssec, tsig, config`);
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
