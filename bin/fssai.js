#!/usr/bin/env node
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { FoscosClient } from '../src/foscos.js';

const USAGE = `Usage: node bin/fssai.js <fssai-number> [--json] [--products] [--timeout <seconds>]

  --json        print the full result, including the raw FoSCoS record, as JSON
  --products    also fetch the food products/categories the business is licensed for
  --timeout     request timeout in seconds (default 30)

FoSCoS normally only answers Indian IP addresses. From outside India, route
through an Indian proxy:  NODE_USE_ENV_PROXY=1 HTTPS_PROXY=http://host:port node bin/fssai.js ...`;

const LABELS = {
  fssaiNumber: 'FSSAI number',
  companyName: 'Company',
  address: 'Address',
  district: 'District',
  state: 'State',
  pincode: 'Pincode',
  licenseCategory: 'Licence type',
  status: 'Status',
  kindOfBusiness: 'Kind of business',
  issuedOn: 'Issued on',
  validUpto: 'Valid up to',
  refId: 'FoSCoS ref ID',
};

export function formatResult(result) {
  const lines = [];
  for (const [key, label] of Object.entries(LABELS)) {
    if (result[key] !== null && result[key] !== undefined) lines.push(`${label.padEnd(17)}: ${result[key]}`);
  }
  if (result.products) {
    lines.push(`Products (${result.products.reduce((n, g) => n + (g.productList?.length ?? 1), 0)})${result.productsError ? `: ${result.productsError}` : ''}`);
    for (const group of result.products) {
      // FoSCoS nests products under their business type: { kobName, productList: [...] }
      if (group.kobName && Array.isArray(group.productList)) lines.push(`  ${group.kobName.trim()}`);
      for (const p of group.productList ?? [group]) {
        const name = p.productName ?? p.fpvsProductName ?? p.itemName ?? p.kobName ?? JSON.stringify(p);
        lines.push(`  - ${String(name).trim()}`);
      }
    }
  }
  return lines.join('\n');
}

async function main(argv) {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: 'boolean', default: false },
        products: { type: 'boolean', default: false },
        timeout: { type: 'string', default: '30' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    });
  } catch (err) {
    console.error(`${err.message}\n\n${USAGE}`);
    return 2;
  }

  const { values, positionals } = args;
  if (values.help || positionals.length !== 1) {
    console.error(USAGE);
    return values.help ? 0 : 2;
  }

  const client = new FoscosClient({ timeoutMs: Number(values.timeout) * 1000 });
  try {
    const result = await client.lookup(positionals[0], { products: values.products });
    if (!result) {
      console.error(`No FoSCoS record found for ${positionals[0]}`);
      return 1;
    }
    console.log(values.json ? JSON.stringify(result, null, 2) : formatResult(result));
    return 0;
  } catch (err) {
    console.error(`Error: ${err.message}`);
    return err.code === 'INVALID_NUMBER' ? 2 : 3;
  }
}

const isEntryPoint = process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntryPoint) {
  process.exitCode = await main(process.argv.slice(2));
}

export { main };
