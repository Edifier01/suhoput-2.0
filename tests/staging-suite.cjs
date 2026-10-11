// Fresh synthetic staging only. Never uses integration credentials or working data.
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const envFile = process.argv[2];
const project = process.argv[3] || 'suhoput-stage-check';
if (!envFile || !/^[a-z0-9][a-z0-9_-]*$/.test(project)) {
  throw new Error('Usage: node tests/staging-suite.cjs <protected-env-file> <unique-test-project>');
}
const base = ['compose', '-p', project, '--env-file', envFile, '-f', 'infra/staging/compose.yaml'];
function compose(args, expected = 0) {
  const result = spawnSync('docker', [...base, ...args], { encoding: 'utf8', timeout: 240000 });
  assert.equal(result.error, undefined, 'Docker command completed');
  if (result.status !== expected) {
    throw new Error(`Staging command ${args[0]} exited ${result.status}: ${result.stderr}`);
  }
  return result.stdout + (expected ? result.stderr : '');
}
async function main() {
  // The model is consumed by Docker below; runtime inspect verifies publication too.
  const model = JSON.parse(compose(['config', '--format', 'json']));
  assert.equal(model.networks.closed.internal, true);
  assert.deepEqual(model.services.wordpress.networks, { closed: null });
  assert.deepEqual(model.services.db.networks, { closed: null });
  assert.deepEqual(model.services.mailpit.networks, { closed: null });
  assert.equal(model.services.scheduler, undefined);
  for (const [name, service] of Object.entries(model.services)) {
    assert.ok(service.image.includes('@sha256:'), `${name} image fixed`);
    assert.ok(!service.privileged && !service.network_mode, `${name} has no host privileges`);
    assert.ok(!service.ports || name === 'proxy', `${name} publishes no service port`);
    for (const volume of service.volumes || []) {
      assert.ok(!volume.source.includes('docker.sock'), `${name} has no Docker socket`);
    }
  }
  for (const port of model.services.proxy.ports) { assert.equal(port.host_ip, '127.0.0.1'); }
  const already = compose(['ps', '-aq']).trim();
  assert.equal(already, '', 'Test project must have no existing containers');
  for (const [kind, resources] of [['volume', model.volumes], ['network', model.networks]]) {
    const listing = spawnSync('docker', [kind, 'ls', '--format', '{{.Name}}'], { encoding: 'utf8' });
    assert.equal(listing.status, 0, `Existing ${kind} names read`);
    const existing = new Set(listing.stdout.trim().split(/\r?\n/));
    for (const resource of Object.values(resources)) {
      assert.ok(!existing.has(resource.name), `Fresh test requires absent ${kind}: ${resource.name}`);
    }
  }
  let started = false;
  try {
    started = true;
    compose(['up', '-d', '--wait']);
    compose(['run', '--rm', 'cli', 'sh', '/bootstrap.sh']);
    const result = compose(['run', '--rm', 'cli', 'wp', 'eval-file', '/tests/staging-safety.php']);
    assert.ok(result.includes('PASS: 12 staging isolation checks'), 'Staging PHP controls passed');
    const blocked = compose(['run', '--rm', 'cli', 'wp', 'suhoput', 'queue', 'tick'], 1);
    assert.ok(blocked.includes('Staging queue execution is disabled.'), 'Manual system tick blocked');
    const cron = await fetch('http://127.0.0.1:18890/wp-cron.php');
    assert.equal(cron.status, 403, 'Direct cron endpoint blocked');
    const site = await fetch('http://127.0.0.1:18890/');
    assert.equal(site.status, 200, 'Staging HTTP reachable on loopback');
    const mail = await fetch('http://127.0.0.1:18891/api/v1/messages');
    assert.equal(mail.status, 200);
    const messages = await mail.json();
    assert.equal(messages.messages.filter(m => m.Subject === 'Staging isolation control').length, 1,
      'Mailpit captured the synthetic control');
    const ids = compose(['ps', '-q', 'proxy']).trim();
    const inspect = spawnSync('docker', ['inspect', ids], { encoding: 'utf8' });
    assert.equal(inspect.status, 0);
    const ports = JSON.parse(inspect.stdout)[0].NetworkSettings.Ports;
    for (const bindings of Object.values(ports)) {
      for (const binding of bindings || []) { assert.equal(binding.HostIp, '127.0.0.1'); }
    }
    console.log('PASS: fresh staging bootstrap, network/HTTP/Mailpit/cron/queue and runtime loopback publication');
  } finally {
    if (started) { compose(['down']); } // Retain only this test project's volumes.
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
