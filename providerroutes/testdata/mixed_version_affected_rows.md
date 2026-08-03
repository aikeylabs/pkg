# 混版受影响行清单（I-11 产物）

> 🤖 **本文件由 `TestExportMixedVersionManifest` 生成，🚫 不要手改。**
> 机器可读真相源：`pkg/providerroutes/testdata/mixed_version_affected_rows.json`，
> 由围栏 `TestFence_I11_MixedVersionDiffIsEnumerated` 逐行比对（新增行未登记即红，
> 登记了却已不再有差异也红）。
>
> **场景**：控制面已升级（新表）而某个 worker 上的代理还是老版（扩表前的 23 行表）。
> 管理员用新控制台建出的凭据，在那台老代理上会打到下表「老代理实际去向」那一列。

**合计 26 行受影响：5 行静默（形状 A）· 21 行有 WARN（形状 B）。**

---

## 🔴 形状 A · 完全静默的错路由

**已知 host + 新 path_prefix。** 老代理的兜底行**永远匹配**，于是新加的路径段被当作
噪声**丢弃**；因为 `LookupByBaseURL` 返回了 `ok=true`，`forward_and_resolve.go` 那条
`proxy.route.not_found` WARN **不触发** —— 日志里什么都没有，用户只看到一个形状不对的
上游错误，看不出是版本偏移。

> ✅ **R-9 定案 B 已缓解**：`resolveStitchComponents` 现在会在这种情况下发出
> `proxy.route.path_discarded` WARN。**转发去向未改变** —— 只是不再无声。

| provider | protocol | 凭据里存的 base_url | 老代理实际去向 | 新代理去向 |
|---|---|---|---|---|
| `deepseek` | anthropic | `https://api.deepseek.com/anthropic/v1` | 🔴 `https://api.deepseek.com/v1/messages` | `https://api.deepseek.com/anthropic/v1/messages` |
| `moonshot` | anthropic | `https://api.moonshot.cn/anthropic/v1` | 🔴 `https://api.moonshot.cn/v1/messages` | `https://api.moonshot.cn/anthropic/v1/messages` |
| `doubao` | anthropic | `https://ark.cn-beijing.volces.com/api/coding/v1` | 🔴 `https://ark.cn-beijing.volces.com/api/v3/v1/messages` | `https://ark.cn-beijing.volces.com/api/coding/v1/messages` |
| `doubao` | openai_compatible | `https://ark.cn-beijing.volces.com/api/coding/v3` | 🔴 `https://ark.cn-beijing.volces.com/api/v3/chat/completions` | `https://ark.cn-beijing.volces.com/api/coding/v3/chat/completions` |
| `qwen` | anthropic | `https://dashscope.aliyuncs.com/api/v2/apps/claude-code-proxy/v1` | 🔴 `https://dashscope.aliyuncs.com/compatible-mode/v1/messages` | `https://dashscope.aliyuncs.com/api/v2/apps/claude-code-proxy/v1/messages` |

---

## 形状 B · `/v1/v1` 双版本段

**全新 host。** 老表里根本没有这个 host → `Stitch` 走 literal-prepend 降级 →
拼出重复的版本段 → 上游 404。**有 `proxy.route.not_found` WARN，可诊断。**

| provider | protocol | 凭据里存的 base_url | 老代理实际去向 | 新代理去向 |
|---|---|---|---|---|
| `vercel_gateway` | openai_compatible | `https://ai-gateway.vercel.sh/v1` | `https://ai-gateway.vercel.sh/v1/v1/chat/completions` | `https://ai-gateway.vercel.sh/v1/chat/completions` |
| `aihubmix` | openai_compatible | `https://aihubmix.com/v1` | `https://aihubmix.com/v1/v1/chat/completions` | `https://aihubmix.com/v1/chat/completions` |
| `ai302` | openai_compatible | `https://api.302.ai/v1` | `https://api.302.ai/v1/v1/chat/completions` | `https://api.302.ai/v1/chat/completions` |
| `aihubmix` | openai_compatible | `https://api.aihubmix.com/v1` | `https://api.aihubmix.com/v1/v1/chat/completions` | `https://api.aihubmix.com/v1/chat/completions` |
| `cerebras` | openai_compatible | `https://api.cerebras.ai/v1` | `https://api.cerebras.ai/v1/v1/chat/completions` | `https://api.cerebras.ai/v1/chat/completions` |
| `fireworks` | openai_compatible | `https://api.fireworks.ai/inference/v1` | `https://api.fireworks.ai/inference/v1/v1/chat/completions` | `https://api.fireworks.ai/inference/v1/chat/completions` |
| `hunyuan` | openai_compatible | `https://api.hunyuan.cloud.tencent.com/v1` | `https://api.hunyuan.cloud.tencent.com/v1/v1/chat/completions` | `https://api.hunyuan.cloud.tencent.com/v1/chat/completions` |
| `minimax` | anthropic | `https://api.minimax.io/anthropic/v1` | `https://api.minimax.io/anthropic/v1/v1/messages` | `https://api.minimax.io/anthropic/v1/messages` |
| `minimax` | openai_compatible | `https://api.minimax.io/v1` | `https://api.minimax.io/v1/v1/chat/completions` | `https://api.minimax.io/v1/chat/completions` |
| `minimax` | anthropic | `https://api.minimaxi.com/anthropic/v1` | `https://api.minimaxi.com/anthropic/v1/v1/messages` | `https://api.minimaxi.com/anthropic/v1/messages` |
| `minimax` | openai_compatible | `https://api.minimaxi.com/v1` | `https://api.minimaxi.com/v1/v1/chat/completions` | `https://api.minimaxi.com/v1/chat/completions` |
| `mistral` | openai_compatible | `https://api.mistral.ai/v1` | `https://api.mistral.ai/v1/v1/chat/completions` | `https://api.mistral.ai/v1/chat/completions` |
| `moonshot` | anthropic | `https://api.moonshot.ai/anthropic/v1` | `https://api.moonshot.ai/anthropic/v1/v1/messages` | `https://api.moonshot.ai/anthropic/v1/messages` |
| `moonshot` | openai_compatible | `https://api.moonshot.ai/v1` | `https://api.moonshot.ai/v1/v1/chat/completions` | `https://api.moonshot.ai/v1/chat/completions` |
| `sambanova` | openai_compatible | `https://api.sambanova.ai/v1` | `https://api.sambanova.ai/v1/v1/chat/completions` | `https://api.sambanova.ai/v1/chat/completions` |
| `stepfun` | openai_compatible | `https://api.stepfun.com/v1` | `https://api.stepfun.com/v1/v1/chat/completions` | `https://api.stepfun.com/v1/chat/completions` |
| `together` | openai_compatible | `https://api.together.ai/v1` | `https://api.together.ai/v1/v1/chat/completions` | `https://api.together.ai/v1/chat/completions` |
| `together` | openai_compatible | `https://api.together.xyz/v1` | `https://api.together.xyz/v1/v1/chat/completions` | `https://api.together.xyz/v1/chat/completions` |
| `zhipu` | anthropic | `https://api.z.ai/api/anthropic/v1` | `https://api.z.ai/api/anthropic/v1/v1/messages` | `https://api.z.ai/api/anthropic/v1/messages` |
| `zhipu` | openai_compatible | `https://api.z.ai/api/paas/v4` | `https://api.z.ai/api/paas/v4/v4/chat/completions` | `https://api.z.ai/api/paas/v4/chat/completions` |
| `qianfan` | openai_compatible | `https://qianfan.baidubce.com/v2` | `https://qianfan.baidubce.com/v2/v2/chat/completions` | `https://qianfan.baidubce.com/v2/chat/completions` |

---

## 发版纪律

🔴 **master 与 worker 必须同版本升级。** staging 上已经发生过只升 master 不升 worker
（P0a：两只 lobster 在退役 master 上孤儿了 10,685 次同步失败没人发现），
所以本清单**不是**「万一」的预案，是「已经发生过一次」的预案。

上表每一行都必须点名进发布说明。🚫 「知道有坑但不写下来」是本项目所有事故的共同形状。
