package providerroutes

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestExportMixedVersionManifest regenerates the I-11 manifest (task P1c.9) and
// the human-readable markdown that the release notes quote.
//
// Env-gated for the same reason as the baseline exporter: the manifest is the
// thing TestFence_I11_MixedVersionDiffIsEnumerated checks against, so a normal
// test run must not be able to rewrite it into agreement with itself.
//
//	AIKEY_REGEN_MIXED_VERSION=1 go test ./pkg/providerroutes -run TestExportMixedVersionManifest -v
//
// Regenerating is correct ONLY when a route row was legitimately added or
// removed — and then the markdown must be re-read by a human, because it is
// what tells operators which credentials break on a half-upgraded fleet.
func TestExportMixedVersionManifest(t *testing.T) {
	if os.Getenv("AIKEY_REGEN_MIXED_VERSION") != "1" {
		t.Skip("generator; set AIKEY_REGEN_MIXED_VERSION=1 to rewrite the manifest")
	}
	oldTbl := tableFromBaseline(t)
	newTbl := Default()

	oldKeys := map[string]bool{}
	for _, r := range oldTbl.All() {
		oldKeys[r.Host+"\x00"+r.PathPrefix] = true
	}

	var rows []mixedVersionRow
	for _, r := range newTbl.All() {
		if oldKeys[r.Host+"\x00"+r.PathPrefix] {
			continue
		}
		stored := EffectiveUpstream(r)
		clientPath := clientPathFor(r.Protocol, r.Version)
		oldUp := stitchWith(t, oldTbl, stored, clientPath)
		newUp := stitchWith(t, newTbl, stored, clientPath)
		if oldUp == newUp {
			continue
		}
		_, known := oldTbl.LookupByBaseURL(stored)
		shape := "B · /v1/v1 duplicate version segment — 404, WARN proxy.route.not_found IS emitted"
		if known {
			shape = "A · SILENT mis-route — the fallback row matched, the path segment was discarded, and NO WARN fires"
		}
		rows = append(rows, mixedVersionRow{
			Host: r.Host, PathPrefix: r.PathPrefix, Provider: r.Provider, Protocol: r.Protocol,
			StoredURL: stored, ClientPath: clientPath,
			OldUpstream: oldUp, NewUpstream: newUp,
			OldRouteKnown: known, Shape: shape,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		// Shape A (silent) first — those are the ones that need naming loudest.
		if rows[i].OldRouteKnown != rows[j].OldRouteKnown {
			return rows[i].OldRouteKnown
		}
		return rows[i].StoredURL < rows[j].StoredURL
	})

	blob, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := filepath.Join("testdata", "mixed_version_affected_rows.json")
	if err := os.WriteFile(out, append(blob, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}

	mdPath := filepath.Join("testdata", "mixed_version_affected_rows.md")
	if err := os.WriteFile(mdPath, []byte(renderMixedVersionMarkdown(rows)), 0o644); err != nil {
		t.Fatalf("write %s: %v", mdPath, err)
	}

	silent := 0
	for _, r := range rows {
		if r.OldRouteKnown {
			silent++
		}
	}
	t.Logf("wrote %s and %s: %d affected row(s), %d of them SILENT (shape A)", out, mdPath, len(rows), silent)
}

func renderMixedVersionMarkdown(rows []mixedVersionRow) string {
	var b strings.Builder
	var silent, loud []mixedVersionRow
	for _, r := range rows {
		if r.OldRouteKnown {
			silent = append(silent, r)
		} else {
			loud = append(loud, r)
		}
	}

	b.WriteString("# 混版受影响行清单（I-11 产物）\n\n")
	b.WriteString("> 🤖 **本文件由 `TestExportMixedVersionManifest` 生成，🚫 不要手改。**\n")
	b.WriteString("> 机器可读真相源：`pkg/providerroutes/testdata/mixed_version_affected_rows.json`，\n")
	b.WriteString("> 由围栏 `TestFence_I11_MixedVersionDiffIsEnumerated` 逐行比对（新增行未登记即红，\n")
	b.WriteString("> 登记了却已不再有差异也红）。\n>\n")
	b.WriteString("> **场景**：控制面已升级（新表）而某个 worker 上的代理还是老版（扩表前的 23 行表）。\n")
	b.WriteString("> 管理员用新控制台建出的凭据，在那台老代理上会打到下表「老代理实际去向」那一列。\n\n")
	b.WriteString(fmt.Sprintf("**合计 %d 行受影响：%d 行静默（形状 A）· %d 行有 WARN（形状 B）。**\n\n", len(rows), len(silent), len(loud)))

	b.WriteString("---\n\n## 🔴 形状 A · 完全静默的错路由\n\n")
	b.WriteString("**已知 host + 新 path_prefix。** 老代理的兜底行**永远匹配**，于是新加的路径段被当作\n")
	b.WriteString("噪声**丢弃**；因为 `LookupByBaseURL` 返回了 `ok=true`，`forward_and_resolve.go` 那条\n")
	b.WriteString("`proxy.route.not_found` WARN **不触发** —— 日志里什么都没有，用户只看到一个形状不对的\n")
	b.WriteString("上游错误，看不出是版本偏移。\n\n")
	b.WriteString("> ✅ **R-9 定案 B 已缓解**：`resolveStitchComponents` 现在会在这种情况下发出\n")
	b.WriteString("> `proxy.route.path_discarded` WARN。**转发去向未改变** —— 只是不再无声。\n\n")
	if len(silent) == 0 {
		b.WriteString("_（本次无此形状的行。）_\n\n")
	} else {
		b.WriteString("| provider | protocol | 凭据里存的 base_url | 老代理实际去向 | 新代理去向 |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, r := range silent {
			b.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | 🔴 `%s` | `%s` |\n",
				r.Provider, r.Protocol, r.StoredURL, r.OldUpstream, r.NewUpstream))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n## 形状 B · `/v1/v1` 双版本段\n\n")
	b.WriteString("**全新 host。** 老表里根本没有这个 host → `Stitch` 走 literal-prepend 降级 →\n")
	b.WriteString("拼出重复的版本段 → 上游 404。**有 `proxy.route.not_found` WARN，可诊断。**\n\n")
	if len(loud) == 0 {
		b.WriteString("_（本次无此形状的行。）_\n\n")
	} else {
		b.WriteString("| provider | protocol | 凭据里存的 base_url | 老代理实际去向 | 新代理去向 |\n")
		b.WriteString("|---|---|---|---|---|\n")
		for _, r := range loud {
			b.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | `%s` | `%s` |\n",
				r.Provider, r.Protocol, r.StoredURL, r.OldUpstream, r.NewUpstream))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n## 发版纪律\n\n")
	b.WriteString("🔴 **master 与 worker 必须同版本升级。** staging 上已经发生过只升 master 不升 worker\n")
	b.WriteString("（P0a：两只 lobster 在退役 master 上孤儿了 10,685 次同步失败没人发现），\n")
	b.WriteString("所以本清单**不是**「万一」的预案，是「已经发生过一次」的预案。\n\n")
	b.WriteString("上表每一行都必须点名进发布说明。🚫 「知道有坑但不写下来」是本项目所有事故的共同形状。\n")
	return b.String()
}
