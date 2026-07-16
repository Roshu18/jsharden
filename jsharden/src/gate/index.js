import { selectProbes } from './probes.js';
import { generateGateKey } from './key-derive.js';
import { encryptBody } from './encrypt.js';
import { buildGateCode } from './gate-source.js';
export function wrapWithGate(armorCode, v2Key) {
  if (typeof armorCode !== 'string') {
    throw new TypeError('wrapWithGate: armorCode must be a string');
  }
  if (!v2Key || typeof v2Key !== 'object') {
    throw new TypeError('wrapWithGate: v2Key must be a key object');
  }
  const selectedProbes = selectProbes(v2Key.seed, 12);
  const {
    gateKey
  } = generateGateKey(v2Key, selectedProbes);
  const {
    encryptedB64
  } = encryptBody(armorCode, gateKey);
  const {
    gateCode
  } = buildGateCode(v2Key, encryptedB64);
  return {
    code: gateCode,
    gateKey
  };
}
export { PROBES, PROBE_POOL, selectProbes } from './probes.js';
export { generateGateKey, deriveKey, presenceProbe } from './key-derive.js';
export { encryptBody, decryptBody, keystreamByte } from './encrypt.js';
export { buildGateCode, PROBE_CHECKS } from './gate-source.js';