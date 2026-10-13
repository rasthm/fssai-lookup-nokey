import { createPublicKey } from 'node:crypto';
import {
  createSession,
  wrapSessionKey,
  encryptPayload,
  decryptResponse,
  verifySignature,
  RESPONSE_PUBLIC_KEY,
  ENCRYPTION_PUBLIC_KEY,
} from './crypto.js';

export const KEY_PATHS = { encryption: '/assets/keys/encPublic.pem', response: '/assets/keys/resPublic.pem' };
export const BASE_URL = 'https://foscos.fssai.gov.in';

const CSRF_PATH = '/gateway/api/auth/csrf-token';
const SEARCH_PATH = '/webgateway/commonauth_readonly/commonapi/getsearchapplicationdetails/1';
const LICENSE_PRODUCTS_PATH = '/gateway/common/signup/getfboapplicationkobproducts/';
const REGISTRATION_PRODUCTS_PATH = '/gateway/common/signup/getfboregistrationkobproducts/';

// licensecategoryid values FoSCoS treats as registrations (the rest are licences)
const REGISTRATION_CATEGORY_IDS = new Set([3, 6, 7, 9]);

const USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';

export class FoscosError extends Error {
  constructor(message, { code, cause } = {}) {
    super(message, { cause });
    this.name = 'FoscosError';
    this.code = code;
  }
}

export function normaliseFssaiNumber(input) {
  const digits = String(input ?? '').replace(/[\s-]/g, '');
  if (!/^\d{14}$/.test(digits)) {
    throw new FoscosError(`"${input}" is not a valid FSSAI number (expected 14 digits)`, {
      code: 'INVALID_NUMBER',
    });
  }
  return digits;
}

// Field names in FoSCoS responses are inconsistent in case (companyname vs companyName),
// so look them up case-insensitively and take the first non-empty match.
function pick(record, ...names) {
  const keys = Object.keys(record);
  for (const name of names) {
    const wanted = name.toLowerCase();
    for (const key of keys) {
      const value = record[key];
      if (key.toLowerCase() === wanted && value !== undefined && value !== null && String(value).trim() !== '') {
        return value;
      }
    }
  }
  return null;
}

export function summariseRecord(record) {
  return {
    fssaiNumber: pick(record, 'licenseno', 'flrsLicenseNo', 'displayrefid'),
    companyName: pick(record, 'companyname', 'fboName'),
    address: pick(record, 'premiseaddress', 'fulladdress', 'address'),
    district: pick(record, 'districtname', 'dist_name'),
    state: pick(record, 'statename', 'state_name'),
    pincode: pick(record, 'premisepincode', 'pincode'),
    licenseCategory: pick(record, 'licensecategoryname', 'apptypedesc', 'categoryName'),
    status: pick(record, 'statusdesc', 'licensestatus', 'statusName', 'status', 'licenseactiveflag'),
    kindOfBusiness: pick(record, 'kobname', 'displaykob', 'kindofbusiness'),
    issuedOn: pick(record, 'issueddate', 'issuedon'),
    validUpto: pick(record, 'expirydate', 'validupto', 'validtill'),
    refId: pick(record, 'refid', 'applicationrefid'),
  };
}

class CookieJar {
  #cookies = new Map();

  store(headers) {
    const setCookies = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
    for (const line of setCookies) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      if (eq > 0) this.#cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }

  get(name) {
    return this.#cookies.get(name);
  }

  get size() {
    return this.#cookies.size;
  }

  header() {
    return [...this.#cookies].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

export class FoscosClient {
  constructor({
    baseUrl = BASE_URL,
    fetch: fetchImpl = globalThis.fetch,
    timeoutMs = 30_000,
    publicKey = RESPONSE_PUBLIC_KEY,
    encryptionKey = ENCRYPTION_PUBLIC_KEY,
    verifySignatures = true,
    fetchKeys = true,
  } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.publicKey = publicKey;
    this.encryptionKey = encryptionKey;
    this.verifySignatures = verifySignatures;
    this.fetchKeys = fetchKeys;
    this.cookies = new CookieJar();
    this.sessionReady = false;
  }

  async #request(path, { method = 'GET', body } = {}) {
    // Fresh AES session key per request, as the FoSCoS frontend does.
    const session = createSession();
    const headers = {
      'x-encrypted-key': wrapSessionKey(session, this.encryptionKey),
      Accept: 'application/json, text/plain, */*',
      'User-Agent': USER_AGENT,
      Origin: this.baseUrl,
      Referer: `${this.baseUrl}/`,
    };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.cookies.size) headers.Cookie = this.cookies.header();
    const xsrf = this.cookies.get('XSRF-TOKEN');
    if (xsrf) headers['X-XSRF-TOKEN'] = decodeURIComponent(xsrf);
    const csrf = this.cookies.get('csrf_token');
    if (csrf) headers['X-CSRF-TOKEN'] = decodeURIComponent(csrf);

    let res;
    try {
      res = await this.fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify({ encryptedPayload: encryptPayload(JSON.stringify(body), session) }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      const timedOut = err?.name === 'TimeoutError' || err?.cause?.code === 'UND_ERR_CONNECT_TIMEOUT';
      throw new FoscosError(
        timedOut
          ? `Timed out reaching ${this.baseUrl}. FoSCoS usually only answers Indian IP addresses; run from India or through an Indian proxy/VPN.`
          : `Could not reach ${this.baseUrl}: ${err.message}`,
        { code: timedOut ? 'TIMEOUT' : 'NETWORK', cause: err },
      );
    }

    this.cookies.store(res.headers);
    const text = await res.text();
    if (!res.ok) {
      throw new FoscosError(`FoSCoS returned HTTP ${res.status} for ${path}: ${text.slice(0, 200)}`, {
        code: 'HTTP_ERROR',
      });
    }
    return this.decode(text, path, session);
  }

  decode(text, path = '', session = null) {
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      throw new FoscosError(`FoSCoS returned non-JSON for ${path}: ${text.slice(0, 200)}`, {
        code: 'BAD_RESPONSE',
      });
    }
    if (json && typeof json === 'object' && typeof json.encryptedResponse === 'string') {
      if (this.verifySignatures && !verifySignature(json.encryptedResponse, json.signature, this.publicKey)) {
        throw new FoscosError(`Signature check failed for ${path}`, { code: 'BAD_SIGNATURE' });
      }
      if (!session) throw new FoscosError(`Encrypted reply for ${path} but no session key`, { code: 'BAD_RESPONSE' });
      return JSON.parse(decryptResponse(json.encryptedResponse, session, json.iv));
    }
    return json;
  }

  // FoSCoS serves its two public keys as static files next to the site. Fetching them
  // keeps lookups working when FSSAI rotates a key; the bundled copies are the fallback.
  async refreshKeys() {
    const fetchPem = async (path) => {
      try {
        const res = await this.fetch(`${this.baseUrl}${path}`, {
          headers: { 'User-Agent': USER_AGENT, Referer: `${this.baseUrl}/` },
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (!res.ok) return null;
        const pem = await res.text();
        createPublicKey(pem); // throws unless it is a real public key (not an HTML error page)
        return pem;
      } catch {
        return null;
      }
    };
    const [enc, res] = await Promise.all([fetchPem(KEY_PATHS.encryption), fetchPem(KEY_PATHS.response)]);
    if (enc) this.encryptionKey = enc;
    if (res) this.publicKey = res;
  }

  async startSession() {
    if (this.sessionReady) return;
    if (this.fetchKeys) await this.refreshKeys();
    await this.#request(CSRF_PATH);
    this.sessionReady = true;
  }

  async search(fssaiNumber) {
    const licenseNo = normaliseFssaiNumber(fssaiNumber);
    await this.startSession();
    const query = { premiseState: null, premiseDistrict: null, companyName: null, flrsLicenseNo: licenseNo };
    const result = await this.#request(SEARCH_PATH, {
      method: 'POST',
      body: query,
    });
    return Array.isArray(result?.paginationListRecords) ? result.paginationListRecords : [];
  }

  async getProducts(record) {
    const refId = pick(record, 'refid');
    if (refId === null) return [];
    const categoryId = Number(pick(record, 'licensecategoryid'));
    const path = REGISTRATION_CATEGORY_IDS.has(categoryId) ? REGISTRATION_PRODUCTS_PATH : LICENSE_PRODUCTS_PATH;
    const products = await this.#request(`${path}${encodeURIComponent(refId)}`);
    return Array.isArray(products) ? products : [];
  }

  /**
   * Look up one FSSAI licence/registration number.
   * Resolves to null when FoSCoS has no record for it.
   */
  async lookup(fssaiNumber, { products = false } = {}) {
    const licenseNo = normaliseFssaiNumber(fssaiNumber);
    const records = await this.search(licenseNo);
    if (records.length === 0) return null;

    const record =
      records.find((r) => String(pick(r, 'licenseno', 'flrsLicenseNo') ?? '') === licenseNo) ?? records[0];
    const result = { ...summariseRecord(record), raw: record };

    if (products) {
      try {
        result.products = await this.getProducts(record);
      } catch (err) {
        result.products = [];
        result.productsError = err.message;
      }
    }
    return result;
  }
}

export async function lookupFssai(fssaiNumber, options = {}) {
  const { products, ...clientOptions } = options;
  return new FoscosClient(clientOptions).lookup(fssaiNumber, { products });
}
