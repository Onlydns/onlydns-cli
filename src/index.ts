/**
 * @onlydns/cli - Official Command-Line Interface for OnlyDNS API (onlydns.com).
 */

export {
  runCli,
  parseArgs,
  createClient,
  showHelp,
  formatRecordsTable,
  formatDnssecStatus,
  formatTsigKeysList,
  formatDomainTsigPermissions,
  cmdDomains,
  cmdRecords,
  cmdDnssec,
  cmdTsig,
  cmdConfig,
} from './cli.js';

export type {
  CliOptions,
  ParsedArgs,
} from './cli.js';

export {
  getConfigDir,
  getConfigFilePath,
  loadConfig,
  saveConfig,
  getStoredApiToken,
  getApiKey,
  setApiKey,
  clearConfig,
} from './config.js';

export type {
  OnlyDNSConfigFile,
} from './config.js';
