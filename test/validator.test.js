import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateUpgradePlan } from '../src/validator.js';
import { parseCidr, overlaps, containsIp } from '../src/cidr.js';

function baseInput() {
  return {
    currentVersion: '1.2.0',
    targetVersion: '1.3.0',
    nodes: [
      { name: 'node-a', cniVersion: '1.2.0', podCIDRs: ['10.10.0.0/24'] },
      { name: 'node-b', cniVersion: '1.2.0', podCIDRs: ['10.10.1.0/24'] },
    ],
    addressAllocations: [
      { node: 'node-a', cidr: '10.10.0.0/24', version: '1.3.0' },
      { node: 'node-b', cidr: '10.10.1.0/24', version: '1.3.0' },
    ],
    routing: {
      protocol: 'bgp',
      advertisements: [
        { cidr: '10.10.0.0/24', knownBy: ['node-a', 'node-b'] },
        { cidr: '10.10.1.0/24', knownBy: ['node-a', 'node-b'] },
      ],
    },
    policy: {
      capabilities: {
        '1.2.0': ['ingress', 'egress'],
        '1.3.0': ['ingress', 'egress'],
      },
    },
    batches: [['node-a'], ['node-b']],
    rollback: {
      images: { '1.2.0': 'reg/cni:1.2.0', '1.3.0': 'reg/cni:1.3.0' },
    },
    pods: [],
  };
}

test('cidr helpers', () => {
  const a = parseCidr('10.10.0.0/24');
  const b = parseCidr('10.10.0.128/25');
  const c = parseCidr('10.11.0.0/24');
  assert.ok(overlaps(a, b));
  assert.ok(!overlaps(a, c));
  assert.ok(containsIp(a, '10.10.0.200'));
  assert.ok(!containsIp(a, '10.10.1.1'));
  assert.throws(() => parseCidr('999.1.1.1/24'));
});

test('happy path: all batches ok, no risks', () => {
  const report = validateUpgradePlan(baseInput());
  assert.equal(report.ok, true);
  assert.deepEqual(
    report.batches.map((b) => b.status),
    ['ok', 'ok'],
  );
  assert.equal(report.blockedPods.length, 0);
  assert.equal(report.crossVersionRisks.length, 0);
  assert.equal(report.addressPoolConflicts.length, 0);
});

test('address pool conflict: overlapping allocations across nodes', () => {
  const input = baseInput();
  input.addressAllocations[1] = { node: 'node-b', cidr: '10.10.0.128/25', version: '1.3.0' };
  const report = validateUpgradePlan(input);
  assert.equal(report.ok, false);
  assert.ok(report.addressPoolConflicts.some((c) => c.type === 'allocation-overlap'));
});

test('address pool conflict: duplicate podCIDRs across nodes', () => {
  const input = baseInput();
  input.nodes[1].podCIDRs = ['10.10.0.0/24'];
  const report = validateUpgradePlan(input);
  assert.equal(report.ok, false);
  assert.ok(report.addressPoolConflicts.some((c) => c.type === 'podcidr-overlap'));
});

test('route not converged: new segment unknown to old node blocks the batch', () => {
  const input = baseInput();
  // node-b (old, batch 2) does not know node-a's new segment.
  input.routing.advertisements = [
    { cidr: '10.10.0.0/24', knownBy: ['node-a'] },
    { cidr: '10.10.1.0/24', knownBy: ['node-a', 'node-b'] },
  ];
  const report = validateUpgradePlan(input);
  assert.equal(report.ok, false);
  assert.equal(report.batches[0].status, 'blocked');
  assert.ok(report.batches[0].reasons.some((r) => r.includes('route-not-converged')));
});

test('policy semantic difference: connectivity check is not sufficient', () => {
  const input = baseInput();
  input.policy.capabilities['1.3.0'] = ['ingress', 'egress', 'adminNetworkPolicy'];
  const report = validateUpgradePlan(input);
  const risk = report.crossVersionRisks.find((r) => r.type === 'policy-semantic-difference');
  assert.ok(risk);
  assert.equal(risk.connectivityCheckSufficient, false);
  assert.deepEqual(risk.addedCapabilities, ['adminNetworkPolicy']);
  // Mixed batches are marked at-risk, not silently ok.
  assert.equal(report.batches[0].status, 'at-risk');
});

test('policy-sensitive pod blocked even when routes converge', () => {
  const input = baseInput();
  input.policy.capabilities['1.3.0'] = ['ingress', 'egress', 'adminNetworkPolicy'];
  input.pods = [
    {
      name: 'payments-0',
      node: 'node-a',
      ip: '10.10.0.9',
      crossNodePeers: ['node-b'],
      policySensitive: true,
    },
  ];
  const report = validateUpgradePlan(input);
  assert.equal(report.ok, false);
  const blocked = report.blockedPods.find((p) => p.pod === 'payments-0');
  assert.ok(blocked);
  assert.ok(blocked.reasons.some((r) => r.includes('policy-sensitive')));
});

test('pod blocked when peer route not converged', () => {
  const input = baseInput();
  input.routing.advertisements = [{ cidr: '10.10.0.0/24', knownBy: ['node-a', 'node-b'] }];
  input.pods = [{ name: 'web-0', node: 'node-a', ip: '10.10.0.5', crossNodePeers: ['node-b'] }];
  const report = validateUpgradePlan(input);
  const blocked = report.blockedPods.find((p) => p.pod === 'web-0');
  assert.ok(blocked);
  assert.ok(blocked.reasons.some((r) => r.includes('not converged')));
});

test('missing rollback image is fatal', () => {
  const input = baseInput();
  delete input.rollback.images['1.3.0'];
  const report = validateUpgradePlan(input);
  assert.equal(report.ok, false);
  assert.ok(
    report.rollbackConditions.some(
      (c) => c.severity === 'fatal' && c.condition.includes('1.3.0'),
    ),
  );
});

test('partial rollback: mixed cluster re-checked, conflict escalates to fatal', () => {
  const input = baseInput();
  input.rollback.partialRollback = ['node-a'];
  let report = validateUpgradePlan(input);
  assert.ok(
    report.rollbackConditions.some(
      (c) => c.node === 'node-a' && c.severity === 'warning',
    ),
  );

  // Introduce an address conflict involving the rolled-back node.
  input.addressAllocations.push({ node: 'node-b', cidr: '10.10.0.0/25', version: '1.3.0' });
  report = validateUpgradePlan(input);
  assert.ok(
    report.rollbackConditions.some((c) => c.node === 'node-a' && c.severity === 'fatal'),
  );
});

test('partial rollback of unknown node is fatal', () => {
  const input = baseInput();
  input.rollback.partialRollback = ['node-zzz'];
  const report = validateUpgradePlan(input);
  assert.ok(
    report.rollbackConditions.some(
      (c) => c.severity === 'fatal' && c.condition.includes('node-zzz'),
    ),
  );
});

test('batch plan defects: duplicate, unknown and unassigned nodes', () => {
  const input = baseInput();
  input.nodes.push({ name: 'node-c', cniVersion: '1.2.0', podCIDRs: ['10.10.2.0/24'] });
  input.batches = [['node-a', 'node-a'], ['node-b', 'node-x']];
  const report = validateUpgradePlan(input);
  assert.equal(report.ok, false);
  assert.ok(report.batches[0].reasons.some((r) => r.includes('multiple batches')));
  assert.ok(report.batches[1].reasons.some((r) => r.includes('unknown node')));
  const last = report.batches.at(-1);
  assert.ok(last.reasons.some((r) => r.includes('node-c')));
});

test('schema problems short-circuit the report', () => {
  const report = validateUpgradePlan({ nodes: [] });
  assert.equal(report.ok, false);
  assert.ok(report.schemaProblems.length > 0);
});

test('example plans match expectations', async () => {
  const ok = JSON.parse(await readFile(new URL('../examples/plan-ok.json', import.meta.url)));
  assert.equal(validateUpgradePlan(ok).ok, true);

  const risky = JSON.parse(
    await readFile(new URL('../examples/plan-risky.json', import.meta.url)),
  );
  const report = validateUpgradePlan(risky);
  assert.equal(report.ok, false);
  assert.ok(report.addressPoolConflicts.length > 0);
  assert.ok(report.crossVersionRisks.length > 0);
  assert.ok(report.blockedPods.length > 0);
  assert.ok(report.rollbackConditions.some((c) => c.severity === 'fatal'));
});
