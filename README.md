# cluster-network-plugin-upgrade-validator
验证 CNI 插件升级中的地址、路由和跨节点兼容

面向 Node.js 24.16.0 的 CNI 滚动升级校验器。集群升级 CNI 插件期间，节点会短暂运行不同版本的 IPAM、路由代理和网络策略实现，新建 Pod 可能因此无法跨节点访问。本工具根据**输入中声明的网络状态**判断升级顺序是否安全，并输出批次、阻塞 Pod、跨版本风险与回滚条件。

## 数据来源说明

**所有网络状态均来自输入文件，校验器不访问任何真实集群。** 节点清单、CNI 版本、PodCIDR、地址分配、路由协议与收敛状态（`routing.advertisements[].knownBy`）、策略能力、滚动批次和回滚镜像全部由调用方以 JSON 提供。校验器是纯函数，无 I/O、无探活、无环境依赖；输入即事实。

## 使用

```bash
node bin/validate.js examples/plan-ok.json      # 通过，退出码 0
node bin/validate.js examples/plan-risky.json   # 不通过，退出码 1，输出完整报告
npm test                                        # node --test
```

## 输入模型

- `currentVersion` / `targetVersion`：升级前后 CNI 版本。
- `nodes[]`：`name`、`cniVersion`、`podCIDRs[]`。
- `addressAllocations[]`：`node`、`cidr`、`version`（该网段由哪个版本分配）。
- `routing`：`protocol`（如 `bgp`）与 `advertisements[]`（`cidr` + `knownBy` 节点列表，表示路由已收敛到哪些节点）。
- `policy`：`capabilities`（每个版本支持的策略能力）与 `incompatiblePairs`（声明语义不兼容的版本对）。
- `batches`：滚动批次，节点名数组的数组，顺序即升级顺序。
- `rollback`：`images`（每个版本对应的回滚镜像）与 `partialRollback`（已部分回滚的节点）。
- `pods[]`：`name`、`node`、`ip`、`crossNodePeers[]`、`policySensitive`。

## 校验规则

- **地址池冲突**：跨节点分配网段重叠、分配网段与他节点 PodCIDR 重叠、节点间 PodCIDR 重叠，均为阻断项。
- **路由收敛**：新版本在某节点分配地址之前，该网段必须对所有仍在旧版本的节点可路由（`knownBy` 覆盖），否则对应批次被阻塞（`route-not-converged`）。
- **策略语义差异**：版本间策略能力有增删或被声明不兼容时，产生 `policy-semantic-difference` 风险，且明确标记 `connectivityCheckSufficient: false`——策略语义不兼容时只检查网络连通是不够的，必须逐流审计策略意图。
- **滚动批次**：节点重复、未知节点、未分配节点均阻塞；混版窗口叠加策略差异时批次标记为 `at-risk`。
- **回滚条件**：缺少任一在用版本的回滚镜像为致命项；每个批次生成失败回滚动作；部分回滚会重新检查混版状态，涉及地址冲突时升级为致命。

## 输出报告

`ok`、`batches[]`（`ok` / `at-risk` / `blocked` 及原因）、`blockedPods[]`、`crossVersionRisks[]`、`rollbackConditions[]`（`info` / `warning` / `fatal`）、`addressPoolConflicts[]`。任一阻断项存在时 `ok=false`，CLI 退出码为 1。

## 结构

- `src/cidr.js`：IPv4 CIDR 解析与重叠判断（无依赖）。
- `src/validator.js`：纯函数 `validateUpgradePlan(input)`。
- `bin/validate.js`：CLI 入口。
- `test/validator.test.js`：`node --test` 用例，覆盖地址池冲突、路由未收敛、策略差异、部分回滚与批次缺陷。
- `examples/`：通过与不通过的示例计划。
