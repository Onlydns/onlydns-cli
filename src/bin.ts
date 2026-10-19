#!/usr/bin/env node

/**
 * Executable CLI entrypoint for @onlydns/cli.
 */

import { runCli } from './cli.js';

runCli(process.argv.slice(2))
  .then((exitCode) => {
    process.exit(exitCode);
  })
  .catch((err) => {
    console.error('Fatal CLI Error:', err);
    process.exit(1);
  });
