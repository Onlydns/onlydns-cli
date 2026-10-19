/**
 * Configuration management for OnlyDNS CLI and TypeScript SDK.
 *
 * Handles credential storage and resolution from environment variables or
 * user configuration files (~/.config/onlydns/config.json).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface OnlyDNSConfigFile {
  api_key?: string;
  api_token?: string;
  token?: string;
  base_url?: string;
  [key: string]: unknown;
}

/**
 * Get configuration directory path (~/.config/onlydns or $XDG_CONFIG_HOME/onlydns).
 */
export function getConfigDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg && xdg.trim()) {
    return path.join(xdg.trim(), 'onlydns');
  }
  return path.join(os.homedir(), '.config', 'onlydns');
}

/**
 * Get primary configuration file path.
 */
export function getConfigFilePath(): string {
  return path.join(getConfigDir(), 'config.json');
}

/**
 * Load configuration object from ~/.config/onlydns/config.json if it exists.
 */
export function loadConfig(): OnlyDNSConfigFile {
  const configPath = getConfigFilePath();
  if (fs.existsSync(configPath)) {
    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      const data = JSON.parse(content);
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return data as OnlyDNSConfigFile;
      }
    } catch {
      return {};
    }
  }

  // Fallback single-file location ~/.config/onlydns.json
  const xdg = process.env.XDG_CONFIG_HOME;
  const fallbackPath = xdg && xdg.trim()
    ? path.join(xdg.trim(), 'onlydns.json')
    : path.join(os.homedir(), '.config', 'onlydns.json');

  if (fs.existsSync(fallbackPath)) {
    try {
      const content = fs.readFileSync(fallbackPath, 'utf-8');
      const data = JSON.parse(content);
      if (data && typeof data === 'object' && !Array.isArray(data)) {
        return data as OnlyDNSConfigFile;
      }
    } catch {
      return {};
    }
  }

  return {};
}

/**
 * Save configuration to ~/.config/onlydns/config.json with secure file permissions.
 */
export function saveConfig(configData: OnlyDNSConfigFile): string {
  const configDir = getConfigDir();
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
  } else {
    try {
      fs.chmodSync(configDir, 0o700);
    } catch {
      // Ignore chmod errors on systems that don't support POSIX permissions
    }
  }

  const configPath = getConfigFilePath();
  const content = JSON.stringify(configData, null, 2) + '\n';
  fs.writeFileSync(configPath, content, { encoding: 'utf-8', mode: 0o600 });
  try {
    fs.chmodSync(configPath, 0o600);
  } catch {
    // Ignore chmod errors
  }

  return configPath;
}

/**
 * Retrieve stored API token from configuration file.
 */
export function getStoredApiToken(): string | undefined {
  const cfg = loadConfig();
  const token = cfg.api_key || cfg.api_token || cfg.token;
  if (typeof token === 'string' && token.trim()) {
    return token.trim();
  }
  return undefined;
}

/**
 * Resolve API key from environment variables or stored configuration.
 *
 * Priority:
 * 1. ONLYDNS_API_KEY environment variable
 * 2. ONLYDNS_API_TOKEN environment variable
 * 3. Stored config file (~/.config/onlydns/config.json)
 */
export function getApiKey(): string | undefined {
  const envKey = process.env.ONLYDNS_API_KEY || process.env.ONLYDNS_API_TOKEN;
  if (envKey && envKey.trim()) {
    return envKey.trim();
  }
  return getStoredApiToken();
}

/**
 * Save or update API key in the configuration file.
 */
export function setApiKey(apiKey: string, baseUrl?: string): string {
  const cfg = loadConfig();
  cfg.api_key = apiKey.trim();
  if (baseUrl && baseUrl.trim()) {
    cfg.base_url = baseUrl.trim();
  }
  return saveConfig(cfg);
}

/**
 * Remove stored configuration file.
 */
export function clearConfig(): boolean {
  const configPath = getConfigFilePath();
  if (fs.existsSync(configPath)) {
    try {
      fs.unlinkSync(configPath);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}
