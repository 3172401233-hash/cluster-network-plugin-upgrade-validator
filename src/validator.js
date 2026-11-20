import { parseCidr, overlaps, containsIp } from './cidr.js';

/**
 * Validate a CNI upgrade plan.
 *
 * All network state (routes, allocations, policy capabilities, convergence)
 * is supplied by the caller via `input`; this module performs no I/O and
 * never probes a live cluster.
 */
export function validateUpgradePlan(input) {
  const problems = validateSchema(input);
  const report = {
    ok: true,
    currentVersion: input?.currentVersion,
    targetVersion: input?.targetVersion,
    batches: [],
    blockedPods: [],
    crossVersionRisks: [],
    rollbackConditions: [],
    addressPoolConflicts: [],
    schemaProblems: problems,
  };
  if (problems.length > 0) {
    report.ok = false;
    return report;
  }

  const nodes = new Map(input.nodes.map((n) => [n.name, n]));

  checkAddressPools(input, report);
  checkPolicySemantics(input, report);
  checkBatches(input, nodes, report);
  checkRollback(input, nodes, report);
  checkPods(input, nodes, report);

  report.ok =
    report.addressPoolConflicts.length === 0 &&
    report.batches.every((b) => b.status !== 'blocked') &&
    report.blockedPods.length === 0 &&
    !report.rollbackConditions.some((c) => c.severity === 'fatal');

  return report;
}

function validateSchema(input) {
  const problems = [];
  if (!input || typeof input !== 'object') return ['input must be an object'];
  for (const key of ['nodes', 'currentVersion', 'targetVersion', 'batches']) {
    if (input[key] === undefined) problems.push(`missing required field: ${key}`);
  }
  if (problems.length > 0) return problems;
  if (!Array.isArray(input.nodes) || input.nodes.length === 0) {
    problems.push('nodes must be a non-empty array');
  }
  if (!Array.isArray(input.batches) || input.batches.length === 0) {
    problems.push('batches must be a non-empty array of node-name arrays');
  }
  return problems;
}

// --- Address pools -------------------------------------------------------

function checkAddressPools(input, report) {
  const allocations = (input.addressAllocations ?? []).map((a) => ({
    ...a,
    range: parseCidr(a.cidr),
  }));

  for (let i = 0; i < allocations.length; i += 1) {
    for (let j = i + 1; j < allocations.length; j += 1) {
      const a = allocations[i];
      const b = allocations[j];
      if (a.node !== b.node && overlaps(a.range, b.range)) {
        report.addressPoolConflicts.push({
          type: 'allocation-overlap',
          cidrA: a.cidr,
          nodeA: a.node,
          cidrB: b.cidr,
          nodeB: b.node,
          detail:
            `allocation ${a.cidr} (${a.node}) overlaps ${b.cidr} (${b.node}); ` +
            'the new version must not allocate from a range old nodes still own',
        });
      }
    }
  }

  for (const alloc of allocations) {
    for (const node of input.nodes) {
      if (node.name === alloc.node) continue;
      for (const podCidr of node.podCIDRs ?? []) {
        if (overlaps(alloc.range, parseCidr(podCidr))) {
          report.addressPoolConflicts.push({
            type: 'allocation-vs-podcidr',
            cidr: alloc.cidr,
            node: alloc.node,
            otherNode: node.name,
            podCIDR: podCidr,
            detail:
              `allocation ${alloc.cidr} on ${alloc.node} overlaps podCIDR ` +
              `${podCidr} of ${node.name}`,
          });
        }
      }
    }
  }

  for (let i = 0; i < input.nodes.length; i += 1) {
    for (let j = i + 1; j < input.nodes.length; j += 1) {
      for (const cidrA of input.nodes[i].podCIDRs ?? []) {
        for (const cidrB of input.nodes[j].podCIDRs ?? []) {
          if (overlaps(parseCidr(cidrA), parseCidr(cidrB))) {
            report.addressPoolConflicts.push({
              type: 'podcidr-overlap',
              nodeA: input.nodes[i].name,
              cidrA,
              nodeB: input.nodes[j].name,
              cidrB,
              detail:
                `podCIDR ${cidrA} of ${input.nodes[i].name} overlaps ` +
                `${cidrB} of ${input.nodes[j].name}`,
            });
          }
        }
      }
    }
  }
}

// --- Policy semantics ----------------------------------------------------

function checkPolicySemantics(input, report) {
  const caps = input.policy?.capabilities ?? {};
  const currentCaps = new Set(caps[input.currentVersion] ?? []);
  const targetCaps = new Set(caps[input.targetVersion] ?? []);

  const added = [...targetCaps].filter((c) => !currentCaps.has(c));
  const removed = [...currentCaps].filter((c) => !targetCaps.has(c));
  const declaredIncompatible = (input.policy?.incompatiblePairs ?? []).some(
    (p) =>
      (p[0] === input.currentVersion && p[1] === input.targetVersion) ||
      (p[0] === input.targetVersion && p[1] === input.currentVersion),
  );

  if (added.length > 0 || removed.length > 0 || declaredIncompatible) {
    report.crossVersionRisks.push({
      type: 'policy-semantic-difference',
      versions: [input.currentVersion, input.targetVersion],
      addedCapabilities: added,
      removedCapabilities: removed,
      declaredIncompatible,
      detail:
        'policy semantics differ between versions; cross-version traffic can be ' +
        'enforced with different rules on each side. A connectivity check alone ' +
        'is NOT sufficient — policy intent must be audited per flow.',
      connectivityCheckSufficient: false,
    });
  }
}

// --- Batches / routing ---------------------------------------------------

function checkBatches(input, nodes, report) {
  const seen = new Set();
  const duplicates = new Set();
  const unknown = new Set();
  for (const batch of input.batches) {
    for (const name of batch) {
      if (seen.has(name)) duplicates.add(name);
      if (!nodes.has(name)) unknown.add(name);
      seen.add(name);
    }
  }
  const missing = [...nodes.keys()].filter((n) => !seen.has(n));

  const upgraded = new Set();
  input.batches.forEach((batch, index) => {
    const reasons = [];
    const risks = [];

    for (const name of batch) {
      if (unknown.has(name)) reasons.push(`unknown node: ${name}`);
      if (duplicates.has(name)) reasons.push(`node appears in multiple batches: ${name}`);
    }

    // Nodes still on the old version once this batch starts upgrading.
    const oldNodes = input.nodes.filter(
      (n) => !upgraded.has(n.name) && !batch.includes(n.name),
    );

    // New-version address segments this batch will bring up.
    const newAllocations = (input.addressAllocations ?? []).filter(
      (a) =>
        batch.includes(a.node) &&
        (a.version ?? input.targetVersion) === input.targetVersion,
    );

    // Core invariant: before the new version allocates an address, every
    // remaining old node must already be able to route that segment.
    for (const alloc of newAllocations) {
      for (const oldNode of oldNodes) {
        if (!routeKnownBy(input, alloc.cidr, oldNode.name)) {
          reasons.push(
            `route-not-converged: ${alloc.cidr} (${alloc.node}, ` +
              `${input.targetVersion}) is not routable from old node ` +
              `${oldNode.name} via ${input.routing?.protocol ?? 'unknown-protocol'}`,
          );
        }
      }
    }

    // Mixed-window policy risk.
    if (oldNodes.length > 0) {
      const policyRisk = report.crossVersionRisks.find(
        (r) => r.type === 'policy-semantic-difference',
      );
      if (policyRisk) {
        risks.push(
          `batch ${index} runs mixed policy versions alongside old nodes: ` +
            oldNodes.map((n) => n.name).join(', '),
        );
      }
    }

    const status = reasons.length > 0 ? 'blocked' : risks.length > 0 ? 'at-risk' : 'ok';
    report.batches.push({ index, nodes: batch, status, reasons, risks });
    batch.forEach((n) => upgraded.add(n));
  });

  if (missing.length > 0) {
    report.batches.push({
      index: input.batches.length,
      nodes: missing,
      status: 'blocked',
      reasons: [`nodes not assigned to any batch: ${missing.join(', ')}`],
      risks: [],
    });
  }
}

function routeKnownBy(input, cidr, nodeName) {
  const advertisements = input.routing?.advertisements ?? [];
  return advertisements.some((adv) => {
    try {
      return (
        overlaps(parseCidr(adv.cidr), parseCidr(cidr)) &&
        (adv.knownBy ?? []).includes(nodeName)
      );
    } catch {
      return false;
    }
  });
}

// --- Rollback ------------------------------------------------------------

function checkRollback(input, nodes, report) {
  const images = input.rollback?.images ?? {};
  const versionsInPlay = new Set([
    input.currentVersion,
    input.targetVersion,
    ...input.nodes.map((n) => n.cniVersion ?? input.currentVersion),
  ]);

  for (const version of versionsInPlay) {
    if (!images[version]) {
      report.rollbackConditions.push({
        severity: 'fatal',
        condition: `rollback image missing for CNI ${version}`,
        action: 'pin a known-good image before starting any batch',
        version,
      });
    }
  }

  input.batches.forEach((batch, index) => {
    report.rollbackConditions.push({
      severity: 'info',
      condition:
        `batch ${index} (${batch.join(', ')}) fails health or convergence checks`,
      action:
        `roll back to ${input.currentVersion} using image ` +
        `${images[input.currentVersion] ?? '<missing>'} and halt the rollout`,
      batchIndex: index,
    });
  });

  // Partial rollback: some nodes returned to the old version while others
  // stay on the new one — re-check the resulting mixed state.
  const rolledBack = input.rollback?.partialRollback ?? [];
  if (rolledBack.length > 0) {
    const stillNew = input.nodes
      .map((n) => n.name)
      .filter((n) => !rolledBack.includes(n));
    for (const name of rolledBack) {
      if (!nodes.has(name)) {
        report.rollbackConditions.push({
          severity: 'fatal',
          condition: `partial rollback references unknown node: ${name}`,
          action: 'fix the rollback plan',
        });
        continue;
      }
      const conflicts = report.addressPoolConflicts.filter(
        (c) => c.nodeA === name || c.nodeB === name || c.node === name,
      );
      report.rollbackConditions.push({
        severity: conflicts.length > 0 ? 'fatal' : 'warning',
        condition:
          `partial rollback of ${name} leaves a mixed cluster with ` +
          `${stillNew.length} node(s) on ${input.targetVersion}`,
        action:
          conflicts.length > 0
            ? `resolve ${conflicts.length} address conflict(s) involving ${name} before re-joining it`
            : `re-verify routes and policy for ${name} against ${input.targetVersion} nodes before re-joining`,
        node: name,
        mixedWith: stillNew,
      });
    }
  }
}

// --- Pods ----------------------------------------------------------------

function checkPods(input, nodes, report) {
  const policyRisk = report.crossVersionRisks.find(
    (r) => r.type === 'policy-semantic-difference',
  );

  for (const pod of input.pods ?? []) {
    const reasons = [];
    const node = nodes.get(pod.node);
    if (!node) {
      reasons.push(`scheduled on unknown node ${pod.node}`);
    } else {
      if (pod.ip) {
        const conflict = report.addressPoolConflicts.find((c) => {
          const cidr = c.cidrA ?? c.cidr ?? c.podCIDR;
          try {
            return containsIp(parseCidr(cidr), pod.ip);
          } catch {
            return false;
          }
        });
        if (conflict) reasons.push(`pod IP ${pod.ip} falls in conflicting segment`);
      }

      for (const peer of pod.crossNodePeers ?? []) {
        const peerNode = nodes.get(peer);
        const peerCidrs = peerNode?.podCIDRs ?? [];
        const converged = peerCidrs.some((cidr) => routeKnownBy(input, cidr, pod.node));
        if (!converged) {
          reasons.push(
            `route to peer node ${peer} not converged on ${pod.node}; ` +
              'new pod may be unreachable across nodes',
          );
        }
      }

      if (pod.policySensitive && policyRisk && (pod.crossNodePeers ?? []).length > 0) {
        reasons.push(
          'policy-sensitive pod communicates across mixed CNI versions; ' +
            'connectivity success does not prove policy equivalence',
        );
      }
    }

    if (reasons.length > 0) {
      report.blockedPods.push({ pod: pod.name, node: pod.node, reasons });
    }
  }
}
