import test from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateOrReservedIp, validateTargetUrl } from './ssrf';

test('isPrivateOrReservedIp blocks IPv4 private, loopback, link-local, metadata, and CGNAT', () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('127.255.0.1'), true);
  assert.equal(isPrivateOrReservedIp('10.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
  assert.equal(isPrivateOrReservedIp('172.31.255.254'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.10'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true); // Cloud metadata
  assert.equal(isPrivateOrReservedIp('100.64.0.1'), true); // CGNAT
  assert.equal(isPrivateOrReservedIp('0.0.0.0'), true);
});

test('isPrivateOrReservedIp blocks IPv6 loopback, ULA, link-local, and IPv4-mapped private IPs', () => {
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('::'), true);
  assert.equal(isPrivateOrReservedIp('fc00::1'), true);
  assert.equal(isPrivateOrReservedIp('fd12:3456::1'), true);
  assert.equal(isPrivateOrReservedIp('fe80::1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:7f00:0001'), true);
});

test('isPrivateOrReservedIp permits genuine public IPs', () => {
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
  assert.equal(isPrivateOrReservedIp('1.1.1.1'), false);
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
  assert.equal(isPrivateOrReservedIp('172.32.0.1'), false); // Outside 172.16/12
  assert.equal(isPrivateOrReservedIp('2606:2800:220:1:248:1893:25c8:1946'), false);
});

test('validateTargetUrl enforces protocol, port, credential, and host restrictions', () => {
  assert.equal(validateTargetUrl('ftp://example.com').valid, false);
  assert.equal(validateTargetUrl('file:///etc/passwd').valid, false);
  assert.equal(validateTargetUrl('javascript:alert(1)').valid, false);
  assert.equal(validateTargetUrl('http://localhost:3000').valid, false);
  assert.equal(validateTargetUrl('http://127.0.0.1').valid, false);
  assert.equal(validateTargetUrl('http://169.254.169.254/latest/meta-data/').valid, false);
  assert.equal(validateTargetUrl('https://user:pass@example.com').valid, false);
  assert.equal(validateTargetUrl('https://example.com:8443').valid, false);
  assert.equal(validateTargetUrl('http://internal.corp').valid, false);

  const ok = validateTargetUrl('example.com');
  assert.equal(ok.valid, true);
  assert.equal(ok.normalizedUrl, 'https://example.com/');
  assert.equal(ok.hostname, 'example.com');
});
