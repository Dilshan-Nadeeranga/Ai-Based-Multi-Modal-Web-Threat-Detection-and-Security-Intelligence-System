/*
 * C2 developer inspector - all client logic (no build step, no libraries, works offline).
 *
 * SECURITY RULE (viva): page content is UNTRUSTED. A phishing page's title can be
 * "<img src=x onerror=...>"; if we ever parsed it as HTML, the scam would run inside
 * our own tool. So:
 *   1. Values from the API reach the screen ONLY through text nodes: el() below
 *      creates elements with document.createElement and sets text with textContent.
 *      HTML-parsing sinks (inner/outer-HTML, insertAdjacent-HTML, document "write",
 *      "eval", the Function constructor) are never used - tests/test_inspector.py
 *      greps this file for them.
 *   2. No href/src is ever set from page data (el() refuses such attributes and
 *      on* handlers). Page URLs are shown as plain text, never as links.
 *   3. The one exception is the Safe Preview iframe: its src is built from a
 *      validated dataset sample id (not page content), points to our own sanitized
 *      endpoint, and the iframe is sandbox="" (no scripts, opaque origin).
 *
 * ADDING A TAB (later parts): call registerTab({...}) - see the "Tab registry"
 * section. Each tab gets the current context and an empty container to fill.
 */
"use strict";

// ---------------------------------------------------------------------------
// Safe DOM helpers
// ---------------------------------------------------------------------------

const BLOCKED_ATTRS = new Set(["href", "src", "srcdoc", "action", "formaction", "xlink:href", "style"]);

/**
 * el("td", {cls: "url", title: "..."}, "text", childNode, ...)
 * Strings become text nodes (never parsed). Attributes that load/navigate or run
 * code are refused, so a page value can never become a link or a script.
 */
function el(tag, opts, ...children) {
  const node = document.createElement(tag);
  const o = opts || {};
  if (o.cls) node.className = o.cls;
  if (o.text !== undefined && o.text !== null) node.textContent = String(o.text);
  if (o.title !== undefined && o.title !== null) node.title = String(o.title);
  for (const [name, value] of Object.entries(o.attrs || {})) {
    const lower = name.toLowerCase();
    if (lower.startsWith("on") || BLOCKED_ATTRS.has(lower)) {
      throw new Error("el(): attribute not allowed: " + name);
    }
    if (value !== false && value !== null && value !== undefined) node.setAttribute(name, String(value));
  }
  if (o.onClick) node.addEventListener("click", o.onClick);
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** Like node.append(), but skips null/false (native append would print "null"). */
function fill(node, ...children) {
  return append(node, children);
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

const $ = (id) => document.getElementById(id);
const fmtInt = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : "—");
const show = (v) => (v === null || v === undefined || v === "" ? "—" : String(v));

function fmtBytes(n) {
  if (typeof n !== "number") return "—";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}

function cut(text, max) {
  const s = show(text);
  return s.length > max ? s.slice(0, max) + " …" : s;
}

const badge = (text, kind) => el("span", { cls: "badge" + (kind ? " " + kind : ""), text });
const yes = (flag, kind) => (flag ? badge("yes", kind) : el("span", { cls: "muted", text: "—" }));
const labelChip = (label) =>
  el("span", { cls: "chip " + (LABEL_CLASSES.has(label) ? label : ""), text: label || "unlabelled" });
const urlText = (url) => el("span", { cls: "url", text: show(url) }); // never a link

const LABEL_CLASSES = new Set(["benign", "phishing", "fake_ecommerce", "crypto_scam", "malware_delivery"]);
const SAMPLE_ID = /^c2_[a-z_]+_\d{6}$/;
const VERSION = /^v\d+(\.\d+)*$/;
const MAX_HTML_BYTES = 5 * 1024 * 1024;

function section(title, ...children) {
  const head = el("h2", {}, ...(Array.isArray(title) ? title : [title]));
  return el("div", { cls: "section" }, head, ...children);
}

function kv(pairs) {
  const dl = el("dl", { cls: "kv" });
  for (const [key, value] of pairs) {
    dl.append(el("dt", { text: key }), append(el("dd"), [value instanceof Node ? value : show(value)]));
  }
  return dl;
}

function countCard(label, value, sub) {
  return el("div", { cls: "count" }, el("div", { cls: "n", text: fmtInt(value) }), el("div", { cls: "l", text: label }),
    sub ? el("div", { cls: "l", text: sub }) : null);
}

/** A table with a header row; rows beyond `limit` are added by a "show more" button. */
function table(headers, rows, rowFn, limit = 300) {
  if (!rows || rows.length === 0) return el("p", { cls: "muted", text: "None." });
  const tbody = el("tbody");
  const wrap = el("div", { cls: "table-wrap" },
    el("table", {}, el("thead", {}, el("tr", {}, headers.map((h) => el("th", { text: h })))), tbody));
  let shown = 0;
  const more = el("button", { attrs: { type: "button" } });
  const addRows = () => {
    const next = rows.slice(shown, shown + limit);
    for (const [i, row] of next.entries()) {
      tbody.append(el("tr", {}, rowFn(row, shown + i).map((cell) => append(el("td"), [cell instanceof Node ? cell : show(cell)]))));
    }
    shown += next.length;
    more.textContent = `Show more (${fmtInt(rows.length - shown)} left)`;
    more.hidden = shown >= rows.length;
  };
  more.addEventListener("click", addRows);
  addRows();
  return el("div", {}, wrap, more);
}

// ---------------------------------------------------------------------------
// API (same origin only; nothing here talks to any other server)
// ---------------------------------------------------------------------------

async function api(path, options) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  if (!response.ok) {
    let detail = response.status + " " + response.statusText;
    try {
      const body = await response.json();
      if (body && body.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch (_) { /* not JSON */ }
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return { data: await response.json(), headers: response.headers };
}

function query(params) {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined && v !== "") q.set(k, String(v));
  const s = q.toString();
  return s ? "?" + s : "";
}

// ---------------------------------------------------------------------------
// Tab registry - later parts add a tab here (no other code needs to change)
// ---------------------------------------------------------------------------
//
//   registerTab({
//     id: "dom-features",               // used in the URL hash (#...&tab=dom-features)
//     title: "DOM Features (Part 3)",
//     enabled: true,                    // false = shown greyed out ("coming in ...")
//     available: (ctx) => true,         // optional: is the tab usable for this page?
//     render: (ctx, container) => {},   // fill the container (text-only helpers above)
//   });
//
// ctx = { page: ParsedPage, kind: "sample" | "pasted", sampleId, version, label,
//         language, parsedSource: "stored" | "on-the-fly" | "api" }.
// A tab that needs more data (e.g. Part 3 features) fetches it in render() and
// fills the container when it arrives.

const TABS = [];

function registerTab(tab) {
  if (!tab.id || !tab.title) throw new Error("registerTab: id and title are required");
  TABS.push({ enabled: true, available: () => true, ...tab });
}

const state = {
  ctx: null,          // the page being inspected
  activeTab: "overview",
  samples: [],
  versions: [],
  loadToken: 0,       // ignores answers to requests that are no longer current
};

// ---- 1. Overview ----------------------------------------------------------

registerTab({
  id: "overview",
  title: "Overview",
  render(ctx, box) {
    const p = ctx.page;
    const m = p.meta || {};
    const inputs = allInputs(p);
    const ext = (p.links || []).filter((l) => l.is_external).length;
    const iframes = (p.embedded || []).filter((e) => e.tag === "iframe" || e.tag === "frame").length;
    fill(box, 
      section("Page",
        kv([
          ["Label", ctx.label ? labelChip(ctx.label) : el("span", { cls: "muted", text: "— (pasted HTML)" })],
          ["Language", ctx.language ? `${ctx.language} (dataset)` + (p.lang_attr ? ` · lang="${p.lang_attr}"` : "") : show(p.lang_attr)],
          ["Title", el("span", { cls: "multi", text: show(p.title) })],
          ["Sample", show(m.sample_id)],
          ["Dataset version", show(m.dataset_version)],
          ["Page URL", urlText(m.page_url)],
          ["Base URL", urlText(m.base_url)],
          ["HTML size", fmtBytes(m.html_size_bytes)],
          ["Encoding / parser", `${show(m.encoding)} / ${show(m.parser_used)}`],
          ["Processing", `${show(m.processing_ms)} ms`],
          ["Truncated", m.truncated ? append(el("span"), [badge("truncated", "warn"), " ", (m.truncation_reasons || []).join("; ")]) : "no"],
          ["Schema / domains", `${show(m.schema_version)} / ${show(m.domain_method)}`],
          ["Source", ctx.parsedSource === "on-the-fly" ? append(el("span"), [badge("processed on the fly", "warn"), " not stored yet - run preprocess_html.py"]) : show(ctx.parsedSource)],
        ])),
      (m.errors || []).length
        ? section("Errors (a failed step keeps its fields empty)", el("div", { cls: "error-box" }, el("ul", {}, m.errors.map((e) => el("li", { text: e })))))
        : null,
      section("Counts",
        el("div", { cls: "cards" },
          countCard("headings", (p.headings || []).length),
          countCard("paragraphs", (p.paragraphs || []).length),
          countCard("forms", (p.forms || []).length),
          countCard("inputs", inputs.length, `${inputs.filter((i) => i.type === "password").length} password`),
          countCard("links", (p.links || []).length, `${ext} external · ${(p.links || []).length - ext} internal`),
          countCard("inline scripts", (p.scripts_inline || []).length),
          countCard("external scripts", (p.scripts_external || []).length),
          countCard("event handlers", (p.event_handlers || []).length),
          countCard("iframes", iframes),
          countCard("comments", (p.comments || {}).count),
          countCard("elements", (p.dom || {}).element_count),
          countCard("max depth", (p.dom || {}).max_depth),
        )),
      section("Time per step (ms)", bars(Object.entries(m.step_ms || {}), (v) => v.toFixed(1))),
    );
  },
});

function allInputs(p) {
  return (p.forms || []).flatMap((f) => f.inputs || []).concat(p.inputs_outside_forms || []);
}

function bars(entries, fmt) {
  if (!entries.length) return el("p", { cls: "muted", text: "None." });
  const max = Math.max(...entries.map(([, v]) => v), 1);
  const grid = el("div", { cls: "bars" });
  for (const [name, value] of entries) {
    const bar = el("div", { cls: "bar" });
    bar.style.width = Math.max(0.5, (100 * value) / max).toFixed(1) + "%"; // a number, not page data
    grid.append(el("span", { cls: "url", text: name, title: name }), el("div", {}, bar), el("span", { cls: "num", text: fmt ? fmt(value) : fmtInt(value) }));
  }
  return grid;
}

// ---- 2. Text ----------------------------------------------------------------

registerTab({
  id: "text",
  title: "Text",
  render(ctx, box) {
    const p = ctx.page;
    const headings = el("div", { cls: "multi" });
    for (const h of p.headings || []) {
      const row = el("div", { cls: "heading" }, el("span", { cls: "lvl", text: "H" + h.level }), h.text);
      row.style.paddingLeft = (Math.min(6, Math.max(1, Number(h.level) || 1)) - 1) * 18 + "px";
      headings.append(row);
    }
    const paragraphs = (p.paragraphs || []);
    fill(box, 
      section("Title & description", kv([
        ["Title", el("span", { cls: "multi", text: show(p.title) })],
        ["Meta description", el("span", { cls: "multi", text: show(p.meta_description) })],
        ["Meta keywords", el("span", { cls: "multi", text: show(p.meta_keywords) })],
        ["lang / charset", `${show(p.lang_attr)} / ${show(p.charset_declared)}`],
      ])),
      section(`Headings (${(p.headings || []).length})`, (p.headings || []).length ? headings : el("p", { cls: "muted", text: "None." })),
      section(`Paragraphs (${paragraphs.length})`,
        paragraphs.length ? el("ol", { cls: "multi scroll" }, paragraphs.slice(0, 500).map((t) => el("li", { text: t }))) : el("p", { cls: "muted", text: "None." }),
        paragraphs.length > 500 ? el("p", { cls: "muted", text: `First 500 of ${paragraphs.length} shown (all are in Raw JSON).` }) : null),
      section(`Visible text (${fmtInt((p.visible_text || "").length)} chars)`, el("pre", { cls: "multi scroll", text: p.visible_text || "(empty)" })),
      section([`Hidden text (${fmtInt((p.hidden_text || "").length)} chars)`, badge("hidden by attribute / inline style / noscript", "warn")],
        el("pre", { cls: "multi scroll hidden-box", text: p.hidden_text || "(none)" })),
    );
  },
});

// ---- 3. Forms -----------------------------------------------------------------

function inputTable(inputs) {
  return table(["tag / type", "name", "label", "placeholder", "hidden", "required", "autocomplete", "value (masked)"], inputs, (i) => [
    i.tag === "input" ? i.type : `${i.tag}`,
    i.name,
    el("span", { cls: "multi", text: show(i.label_text) }),
    el("span", { cls: "multi", text: show(i.placeholder) }),
    yes(i.hidden, "warn"),
    yes(i.required),
    i.autocomplete,
    i.value_present ? el("span", { cls: "url", text: show(i.value_masked) }) : el("span", { cls: "muted", text: "—" }),
  ]);
}

registerTab({
  id: "forms",
  title: "Forms",
  render(ctx, box) {
    const p = ctx.page;
    if (!(p.forms || []).length && !(p.inputs_outside_forms || []).length) {
      fill(box, el("p", { cls: "empty", text: "No forms and no inputs on this page." }));
      return;
    }
    for (const f of p.forms || []) {
      fill(box, el("div", { cls: "card" },
        el("h3", {}, `Form #${f.index}`, badge(f.method, "info"),
          f.is_external_action ? badge("EXTERNAL ACTION", "danger") : badge("same site", "ok"),
          f.id ? badge("id=" + f.id) : null, f.name ? badge("name=" + f.name) : null),
        kv([
          ["Action (resolved)", f.action_abs ? urlText(f.action_abs) : el("span", { cls: "muted", text: "— (no URL, e.g. javascript:)" })],
          ["Action (as written)", urlText(f.action_raw)],
          ["Action domain", show(f.action_domain)],
          ["Enctype", show(f.enctype)],
        ]),
        el("h3", {}, `Inputs (${(f.inputs || []).length})`),
        inputTable(f.inputs || []),
        el("h3", {}, `Buttons (${(f.buttons || []).length})`),
        table(["type", "text", "value"], f.buttons || [], (b) => [b.type, el("span", { cls: "multi", text: show(b.text) }), b.value]),
      ));
    }
    if ((p.inputs_outside_forms || []).length) {
      fill(box, el("div", { cls: "card" },
        el("h3", {}, `Inputs outside any form (${p.inputs_outside_forms.length})`, badge("often submitted by JavaScript", "warn")),
        inputTable(p.inputs_outside_forms)));
    }
  },
});

// ---- 4. Scripts -----------------------------------------------------------------

const SCRIPT_PREVIEW_CHARS = 3000;

registerTab({
  id: "scripts",
  title: "Scripts",
  render(ctx, box) {
    const p = ctx.page;
    const inline = p.scripts_inline || [];
    const list = el("div");
    for (const s of inline) {
      const details = el("details", {},
        el("summary", {}, `#${s.index} · ${s.position} · ${fmtInt(s.chars)} chars`, s.type ? ` · type=${s.type}` : "",
          s.content_truncated ? " · " : "", s.content_truncated ? badge("capped", "warn") : null));
      // The <pre> is built only when opened: a page can have hundreds of big scripts.
      details.addEventListener("toggle", () => {
        if (!details.open || details.dataset.filled) return;
        details.dataset.filled = "1";
        const text = (s.content || "").slice(0, SCRIPT_PREVIEW_CHARS);
        details.append(el("pre", { cls: "scroll", text: text + ((s.content || "").length > SCRIPT_PREVIEW_CHARS ? `\n\n… first ${SCRIPT_PREVIEW_CHARS} chars shown (full text in Raw JSON)` : "") }));
      });
      list.append(details);
    }
    const data = (p.structured_data || []).concat(p.templates || []);
    fill(box, 
      section(`Inline scripts (${inline.length})`, inline.length ? list : el("p", { cls: "muted", text: "None." }),
        el("p", { cls: "muted", text: "Shown as text only - never executed (static analysis: see the JS Analysis (Part 7) tab)." })),
      section(`External scripts (${(p.scripts_external || []).length})`,
        table(["src", "domain", "site", "async / defer", "integrity", "crossorigin"], p.scripts_external || [], (s) => [
          urlText(s.src_abs || s.src_raw), s.domain,
          s.is_external ? badge("external", "danger") : badge("same site", "ok"),
          [s.async ? "async" : "", s.defer ? "defer" : ""].filter(Boolean).join(" ") || "—",
          yes(s.has_integrity, "ok"), s.crossorigin,
        ])),
      section(`Event handlers (${(p.event_handlers || []).length})`,
        table(["tag", "attribute", "code"], p.event_handlers || [], (h) => [h.tag, h.attribute, el("span", { cls: "url", text: cut(h.code, 400) })])),
      section(`javascript: URLs (${(p.javascript_urls || []).length})`,
        table(["tag", "attribute", "code"], p.javascript_urls || [], (j) => [j.tag, j.attribute, el("span", { cls: "url", text: cut(j.code, 400) })])),
      section(`Data blocks: JSON-LD / templates (${data.length})`,
        table(["type", "chars", "content (start)"], data, (d) => [d.type, fmtInt(d.chars), el("span", { cls: "url", text: cut(d.content, 300) })])),
    );
  },
});

// ---- 5. Links & Resources ---------------------------------------------------------

registerTab({
  id: "links",
  title: "Links & Resources",
  render(ctx, box) {
    const p = ctx.page;
    const links = p.links || [];
    const ext = links.filter((l) => l.is_external).length;
    const ratio = el("div", { cls: "ratio", title: `${links.length - ext} internal / ${ext} external` });
    if (links.length) {
      const i = el("div", { cls: "int" });
      i.style.width = ((100 * (links.length - ext)) / links.length).toFixed(1) + "%";
      const e = el("div", { cls: "ext" });
      e.style.width = ((100 * ext) / links.length).toFixed(1) + "%";
      ratio.append(i, e);
    }
    const css = p.css || {};
    const refresh = (p.meta_tags || []).find((t) => (t.http_equiv || "").toLowerCase() === "refresh");
    fill(box, 
      section(`Links (${links.length})`,
        el("div", { cls: "muted", text: links.length ? `internal ${links.length - ext} (${Math.round((100 * (links.length - ext)) / links.length)}%) · external ${ext} (${Math.round((100 * ext) / links.length)}%)` : "No links." }),
        links.length ? ratio : null,
        table(["domain", "site", "text", "URL", "rel / target"], links, (l) => [
          l.domain, l.is_external ? badge("external", "danger") : badge("internal", "ok"),
          el("span", { cls: "multi", text: show(l.text) }), urlText(l.href_abs || l.href_raw),
          [l.rel, l.target].filter(Boolean).join(" / ") || "—",
        ])),
      section("Stylesheets & CSS",
        kv([
          ["<style> blocks", `${fmtInt(css.inline_style_blocks_count)} (${fmtInt(css.inline_style_total_chars)} chars)`],
          ["style=\"\" attributes", fmtInt(css.style_attribute_count)],
        ]),
        table(["stylesheet", "domain", "site"], css.external_stylesheets || [], (s) => [urlText(s.href_abs), s.domain, s.is_external ? badge("external", "danger") : badge("same site", "ok")])),
      section(`Iframes & embeds (${(p.embedded || []).length})`,
        table(["tag", "src", "domain", "site", "size", "hidden"], p.embedded || [], (e) => [
          e.tag, urlText(e.src_abs), e.domain, e.is_external ? badge("external", "danger") : badge("same site", "ok"),
          `${show(e.width)} × ${show(e.height)}`, e.hidden ? badge("HIDDEN", "danger") : el("span", { cls: "muted", text: "—" }),
        ])),
      section([`Meta tags (${(p.meta_tags || []).length})`, refresh ? badge("meta refresh", "warn") : null],
        refresh ? el("p", { cls: "note" }, "Refresh redirect to ", urlText(refresh.redirect_url || refresh.content)) : null,
        table(["name / property / http-equiv", "content", "redirect URL"], p.meta_tags || [], (t) => [
          t.name || t.property || (t.http_equiv ? "http-equiv=" + t.http_equiv : "—"),
          el("span", { cls: "multi", text: cut(t.content, 300) }), t.redirect_url ? urlText(t.redirect_url) : "—",
        ])),
    );
  },
});

// ---- 6. DOM -------------------------------------------------------------------------

function nodeLabel(n) {
  const parts = [el("span", { cls: "tag", text: n.tag })];
  if (n.id) parts.push(el("span", { cls: "attr", text: "#" + n.id }));
  if (n.class && n.class.length) parts.push(el("span", { cls: "attr", text: "." + n.class.join(".") }));
  if (n.type) parts.push(el("span", { cls: "attr", text: ` type=${n.type}` }));
  if (n.name) parts.push(el("span", { cls: "attr", text: ` name=${n.name}` }));
  if (n.href_domain) parts.push(el("span", { cls: "attr", text: ` → ${n.href_domain}` }));
  return parts;
}

/** One tree row; children are created only when expanded (skeletons have 3000 nodes). */
function treeItem(node, openDepth) {
  const kids = node.children || [];
  const li = el("li");
  if (!kids.length) {
    li.append(el("span", { cls: "leaf" }), ...nodeLabel(node));
    return li;
  }
  const toggle = el("button", { cls: "tog", attrs: { type: "button", "aria-expanded": "false" }, text: "▸" });
  const childList = el("ul");
  childList.hidden = true;
  let built = false;
  const setOpen = (open) => {
    if (open && !built) {
      built = true;
      childList.append(...kids.map((k) => treeItem(k, openDepth - 1)));
    }
    childList.hidden = !open;
    toggle.textContent = open ? "▾" : "▸";
    toggle.setAttribute("aria-expanded", String(open));
  };
  toggle.addEventListener("click", () => setOpen(childList.hidden));
  li.append(toggle, ...nodeLabel(node), el("span", { cls: "muted", text: ` (${kids.length})` }), childList);
  if (openDepth > 0) setOpen(true);
  return li;
}

registerTab({
  id: "dom",
  title: "DOM",
  render(ctx, box) {
    const d = ctx.page.dom || {};
    const tags = Object.entries(d.tag_counts || {}).sort((a, b) => b[1] - a[1]);
    const skeletonNotes = ((ctx.page.meta || {}).truncation_reasons || []).filter((r) => /skeleton/i.test(r));
    const tree = el("div", { cls: "tree" });
    if (d.skeleton) tree.append(el("ul", {}, treeItem(d.skeleton, 3)));
    fill(box, 
      section("Size", el("div", { cls: "cards" },
        countCard("nodes", d.node_count), countCard("elements", d.element_count),
        countCard("max depth", d.max_depth), countCard("distinct tags", tags.length))),
      section(`Tag counts (top ${Math.min(40, tags.length)} of ${tags.length})`, bars(tags.slice(0, 40))),
      section(["Skeleton tree", skeletonNotes.length ? badge("capped", "warn") : null],
        skeletonNotes.length ? el("p", { cls: "muted", text: skeletonNotes.join("; ") }) : null,
        d.skeleton ? tree : el("p", { cls: "muted", text: "No skeleton." })),
    );
  },
});

// ---- 7. Raw JSON ----------------------------------------------------------------------

registerTab({
  id: "json",
  title: "Raw JSON",
  render(ctx, box) {
    const text = JSON.stringify(ctx.page, null, 2);
    const msg = el("span", { cls: "muted", text: `${fmtBytes(new Blob([text]).size)}` });
    const copy = el("button", { attrs: { type: "button" }, text: "Copy", onClick: async () => {
      try {
        await navigator.clipboard.writeText(text);
        msg.textContent = "Copied.";
      } catch (_) {
        const range = document.createRange();
        range.selectNodeContents(pre);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        msg.textContent = "Clipboard blocked - text selected, press Ctrl+C.";
      }
    } });
    const pre = el("pre", { cls: "multi", text });
    fill(box, el("div", { cls: "toolbar" }, copy, msg), pre);
  },
});

// ---- 8. Safe Preview --------------------------------------------------------------------

registerTab({
  id: "preview",
  title: "Safe Preview",
  available: (ctx) => ctx.kind === "sample",
  render(ctx, box) {
    if (ctx.kind !== "sample" || !SAMPLE_ID.test(ctx.sampleId || "")) {
      fill(box, el("p", { cls: "empty", text: "Safe Preview is only available for dataset samples (pasted HTML is never rendered)." }));
      return;
    }
    // sandbox="" = no scripts, no forms, no popups, opaque origin. The src is our own
    // endpoint + a validated sample id (not page content) - see rule 3 at the top.
    const frame = document.createElement("iframe");
    frame.className = "preview-frame";
    frame.setAttribute("sandbox", "");
    frame.setAttribute("referrerpolicy", "no-referrer");
    frame.title = "Sanitized preview of " + ctx.sampleId;
    frame.src = `/api/v1/dev/samples/${encodeURIComponent(ctx.sampleId)}/safe-preview` + query({ version: ctx.version });
    fill(box, 
      el("p", { cls: "note", text: "Sanitized copy — original never rendered. Scripts, links, forms, frames and outside resources were removed (Part 1 safe_preview) and the frame is sandboxed." }),
      frame,
    );
  },
});

// ---- 9. DOM Features (Part 3) ----------------------------------------------------------------
//
// Part 3's fixed-order feature vector + evidence. Data: the dictionary (names, groups,
// descriptions, per-label medians from reports/dom_features) and the DomResult of
// this page (dev endpoint for samples, POST /api/v1/dom-features for pasted HTML).

const domCache = { dictionary: new Map(), results: new WeakMap(), predictions: new WeakMap() };
const SEVERITY_KIND = { high: "danger", medium: "warn", info: "info" };

function cached(map, key, load) {
  if (!map.has(key)) {
    const promise = load().catch((error) => {
      map.delete(key); // do not keep a failure: the next visit tries again
      throw error;
    });
    map.set(key, promise);
  }
  return map.get(key);
}

function domDictionary(version) {
  return cached(domCache.dictionary, version || "", () =>
    api("/api/v1/dev/dom-dictionary" + query({ version })).then((r) => r.data));
}

function domResult(ctx) {
  return cached(domCache.results, ctx, () => {
    if (ctx.kind === "sample") {
      return api(`/api/v1/dev/samples/${encodeURIComponent(ctx.sampleId)}/dom-features` + query({ version: ctx.version }))
        .then((r) => ({ data: r.data, source: r.headers.get("X-Features-Source") || "stored" }));
    }
    return api("/api/v1/dom-features", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ html: ctx.html || "", url: ctx.url || null }),
    }).then((r) => ({ data: r.data, source: "api" }));
  });
}

function domPrediction(ctx) {
  return cached(domCache.predictions, ctx, () =>
    api(`/api/v1/dev/samples/${encodeURIComponent(ctx.sampleId)}/dom-prediction` + query({ version: ctx.version }))
      .then((r) => r.data));
}

function fmtPct(p) {
  return typeof p === "number" ? (100 * p).toFixed(1) + " %" : "—";
}

// Part 4: the DOM baseline's answer for a dataset sample (best model by CV macro-F1).
// Fetched separately, so a missing model only shows a note and never breaks the tab.
async function renderPrediction(ctx, box) {
  const title = "DOM baseline prediction (Part 4)";
  if (ctx.kind !== "sample") {
    fill(box, section(title, el("p", { cls: "muted", text: "Shown for dataset samples (the models of that version); pasted HTML has no prediction here." })));
    return;
  }
  fill(box, el("p", { cls: "muted", text: "Loading DOM baseline prediction…" }));
  let p;
  try {
    p = await domPrediction(ctx);
  } catch (error) {
    if (state.ctx !== ctx || !box.isConnected) return;
    fill(clear(box), section(title, el("p", { cls: "note", text: error.status === 404 ? error.message : "Prediction failed: " + error.message })));
    return;
  }
  if (state.ctx !== ctx || !box.isConnected) return;
  const best = (p.models || []).find((m) => m.model === p.best_model) || {};
  const matches = p.true_label ? p.true_label === p.predicted : null;
  const probabilities = Object.entries(p.probabilities || {}).sort((a, b) => b[1] - a[1]);
  const pushes = p.contributions || [];
  fill(clear(box), section(title, el("div", { cls: "card" },
    el("h3", {},
      "Predicted", labelChip(p.predicted), el("strong", { text: fmtPct(p.probabilities[p.predicted]) }),
      badge(`${show(best.display_name)} · best by CV macro-F1 ${fmtValue(best.cv_macro_f1)}`, "info"),
      p.pilot ? badge(`PILOT model (${p.dataset_version}, ${p.classes.length} classes)`, "warn") : null,
      matches === null ? null : badge(matches ? "matches the label" : `label is ${p.true_label}`, matches ? "ok" : "danger"),
      p.split ? badge(`split: ${p.split}`, p.split === "test" ? "info" : null) : null,
      p.misclassified_test ? badge("misclassified (test)", "danger") : null),
    (() => { const b = bars(probabilities, fmtPct); b.classList.add("wide"); return b; })(),
    el("h3", { cls: "heading" }, `Top ${pushes.length} contributing features`, badge(pushes.length ? pushes[0].method : "—")),
    pushes.length
      ? table(["feature", "value", "push", `on "${p.predicted}"`], pushes, (c) => [
        el("span", { text: c.name, title: c.description }),
        fmtValue(c.value),
        badge(c.direction === "towards" ? "pushes towards" : "pushes away from", c.direction === "towards" ? "info" : null),
        (c.contribution > 0 ? "+" : "") + fmtValue(c.contribution),
      ])
      : el("p", { cls: "muted", text: "No feature moves this prediction." }),
    el("p", { cls: "muted", text: "All models: " + (p.models || []).map((m) => `${m.display_name} → ${m.predicted} (${fmtPct(m.probabilities[m.predicted])})`).join(" · ") }),
    p.pilot ? el("p", { cls: "note", text: `Pilot: trained on ${p.classes.join(", ")} only - it cannot answer ${Object.keys(p.excluded_classes || {}).join(", ") || "other classes"}.` }) : null)));
}

function fmtValue(value) {
  if (typeof value !== "number") return show(value);
  return Number.isInteger(value) ? fmtInt(value) : String(Math.round(value * 10000) / 10000);
}

function detailText(details) {
  // Details come from the page (already PII-masked by Part 2): shown as plain text only.
  return Object.entries(details || {})
    .map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`)
    .join(" · ");
}

function mediansCell(name, medians) {
  const labels = Object.keys(medians);
  if (!labels.length) return el("span", { cls: "muted", text: "—" });
  return append(el("span", { cls: "muted" }),
    labels.map((label, i) => [i ? " · " : "", `${label} ${fmtValue(medians[label][name])}`]));
}

registerTab({
  id: "dom-features",
  title: "DOM Features (Part 3)",
  async render(ctx, box) {
    fill(box, el("p", { cls: "muted", text: "Loading DOM features…" }));
    const [dictionary, result] = await Promise.all([domDictionary(ctx.version), domResult(ctx)]);
    if (state.ctx !== ctx || !box.isConnected) return; // the user moved on meanwhile
    const r = result.data;
    const features = r.features || {};
    const medians = dictionary.label_medians || {};
    const specs = dictionary.features || [];
    clear(box);

    fill(box,
      el("div", { cls: "toolbar" },
        badge(r.feature_set_version, "info"),
        badge(`${specs.length} features`),
        badge(result.source === "on-the-fly" ? "computed on the fly" : result.source, result.source === "on-the-fly" ? "warn" : null),
        el("span", { cls: "muted", text: `tree from ${r.tree_source} · ${fmtValue(r.processing_ms)} ms` })),
      (r.errors || []).length ? el("div", { cls: "error-box" }, el("ul", {}, r.errors.map((e) => el("li", { text: e })))) : null,
      (r.warnings || []).length ? el("p", { cls: "note", text: "Note: " + r.warnings.join(" · ") }) : null,
      Object.keys(medians).length ? null
        : el("p", { cls: "note", text: `No label medians yet - run: python scripts/extract_dom_features.py run --version ${ctx.version || "<version>"}` }),
    );

    const predictionBox = el("div");
    fill(box, predictionBox);
    renderPrediction(ctx, predictionBox).catch((error) =>
      fill(clear(predictionBox), el("div", { cls: "error-box", text: "Prediction card failed: " + error.message })));

    // Evidence first: the "why" in words, most severe first.
    const evidence = r.evidence || [];
    fill(box, section(`Evidence (${evidence.length})`,
      evidence.length
        ? el("div", {}, evidence.map((item) => el("div", { cls: "card" },
          el("h3", {}, badge(item.severity.toUpperCase(), SEVERITY_KIND[item.severity]), el("span", { cls: "multi", text: item.message })),
          el("div", { cls: "muted url", text: `${item.feature} = ${fmtValue(item.value)}` + (detailText(item.details) ? ` · ${detailText(item.details)}` : "") }))))
        : el("p", { cls: "muted", text: "No evidence: none of the evidence features is non-zero." })));

    // Grouped cards: the non-zero features of each group, with label medians to compare.
    const grid = el("div");
    for (const group of dictionary.groups || []) {
      const inGroup = specs.filter((s) => s.group === group);
      const nonzero = inGroup.filter((s) => features[s.name]);
      grid.append(el("div", { cls: "card" },
        el("h3", {}, group, badge(`${nonzero.length} / ${inGroup.length} non-zero`)),
        nonzero.length
          ? table(["feature", "value", "median per label"], nonzero, (s) => [
            el("span", { cls: "url", text: s.name, title: s.description }),
            el("strong", { text: fmtValue(features[s.name]) }),
            mediansCell(s.name, medians),
          ])
          : el("p", { cls: "muted", text: "All zero." })));
    }
    fill(box, section("Feature groups (non-zero values)", grid));

    // Every feature, in vector order, built only when asked for.
    const all = el("div");
    all.hidden = true;
    const toggle = el("button", { attrs: { type: "button" }, text: "Show all features" });
    toggle.addEventListener("click", () => {
      if (!all.firstChild) {
        all.append(table(["#", "feature", "group", "type", "value", "median per label", "description"], specs, (s, i) => [
          String(i + 1), el("span", { cls: "url", text: s.name }), s.group, s.type,
          features[s.name] ? el("strong", { text: fmtValue(features[s.name]) }) : el("span", { cls: "muted", text: fmtValue(features[s.name]) }),
          mediansCell(s.name, medians), s.description,
        ], 100));
      }
      all.hidden = !all.hidden;
      toggle.textContent = all.hidden ? "Show all features" : "Hide all features";
    });
    fill(box, section("All features (vector order)", toggle, all));
  },
});

// ---- 8. JS Analysis (Part 7) ------------------------------------------------------
//
// Static JavaScript analysis: what the page's scripts USE (eval, fetch, cookies, ...),
// where, and with which arguments. Part 7 does not judge intent (Part 8 does).
// Snippets are page code: shown ONLY as text (textContent, monospace), never parsed.

const jsCache = new WeakMap();
const JS_CATEGORY_KIND = {
  code_execution: "danger", form_submission: "danger", clipboard: "danger",
  dom_write: "warn", html_injection: "warn", network_fetch: "warn", network_xhr: "warn",
  redirect: "warn", cookie: "warn", credential_access: "warn", download: "warn",
};

function jsAnalysis(ctx) {
  return cached(jsCache, ctx, () => {
    if (ctx.kind === "sample") {
      return api(`/api/v1/dev/samples/${encodeURIComponent(ctx.sampleId)}/js-analysis` + query({ version: ctx.version }))
        .then((r) => ({ data: r.data, source: r.headers.get("X-Js-Source") || "stored" }));
    }
    return api("/api/v1/js-analysis", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ html: ctx.html || "", url: ctx.url || null }),
    }).then((r) => ({ data: r.data, source: "api" }));
  });
}

const codeText = (text) => el("span", { cls: "url", text: show(text) }); // monospace, text only

function detectionRow(d, scripts) {
  const script = scripts[d.script_index] || {};
  const args = d.args || {};
  const url = args.url
    ? el("span", {}, codeText(args.url), " ",
      args.url_is_external ? badge("external", "danger") : badge("same site", "ok"))
    : (args.literal_value ? codeText(args.literal_value) : el("span", { cls: "muted", text: "—" }));
  const facts = [d.selector ? `selector ${d.selector}` : "", d.event_type ? `event ${d.event_type}` : "",
    d.assigned_to ? `→ ${d.assigned_to}` : "", args.http_method || "",
    (args.identifiers_used || []).length ? "uses " + args.identifiers_used.slice(0, 6).join(", ") : "",
    d.enclosing_function ? `in ${d.enclosing_function}` : ""].filter(Boolean).join(" · ");
  return [
    el("span", {}, el("strong", { text: d.api }), " ", badge(d.category, JS_CATEGORY_KIND[d.category])),
    `${d.source} #${d.script_index}`,
    `${d.line}:${d.column}`,
    d.access,
    el("div", {}, codeText(d.snippet), facts ? el("div", { cls: "muted", text: facts }) : null),
    url,
    el("span", {}, d.in_library ? badge(`library: ${script.library || "?"}`, "info") : null, " ",
      d.confidence === "low" ? badge("low confidence", "warn") : badge("high", "ok")),
  ];
}

function scriptCard(s) {
  const o = s.obfuscation;
  return el("div", { cls: "card" },
    el("h3", {}, `#${s.index} ${s.origin}`,
      badge(s.parser, s.parser === "tree-sitter" ? "ok" : "warn"),
      s.library ? badge(`library: ${s.library}`, "info") : null,
      s.truncated ? badge("truncated", "warn") : null,
      s.timed_out ? badge("parse timeout", "danger") : null,
      s.has_error ? badge(`parse errors ${(100 * s.error_ratio).toFixed(1)} %`, "warn") : null,
      s.detections ? badge(`${s.detections} detection(s)`) : null,
      o && o.minified ? badge("minified") : null,
      ...(o ? o.signatures.map((x) => badge(x, "danger")) : [])),
    o ? kv([
      ["characters", `${fmtInt(s.analyzed_chars)} analysed of ${fmtInt(s.chars)}`],
      ["lines / longest", `${fmtInt(o.lines)} / ${fmtInt(o.max_line_length)} chars`],
      ["entropy", `${fmtValue(o.entropy)} bits/char`],
      ["whitespace / symbols", `${fmtPct(o.whitespace_ratio)} / ${fmtPct(o.non_alnum_ratio)}`],
      ["escapes hiding text", fmtPct(o.escape_ratio)],
      ["identifiers", `${fmtInt(o.identifier_count)} · avg ${fmtValue(o.avg_identifier_length)} chars · ${fmtPct(o.single_char_identifier_ratio)} one-letter · ${fmtPct(o.hex_identifier_ratio)} _0x names`],
      ["longest string / string array", `${fmtInt(o.max_string_length)} / ${fmtInt(o.string_array_size)}`],
    ]) : el("p", { cls: "muted", text: s.note || "Not analysed." }),
    s.note && o ? el("p", { cls: "note", text: s.note }) : null);
}

registerTab({
  id: "js-analysis",
  title: "JS Analysis (Part 7)",
  async render(ctx, box) {
    fill(box, el("p", { cls: "muted", text: "Analysing JavaScript (static, nothing is executed)…" }));
    const result = await jsAnalysis(ctx);
    if (state.ctx !== ctx || !box.isConnected) return; // the user moved on meanwhile
    const r = result.data;
    const meta = r.meta || {};
    const summary = r.summary || {};
    const scripts = r.scripts || [];
    const detections = r.detections || [];
    clear(box);

    fill(box,
      el("div", { cls: "toolbar" },
        badge(r.feature_set_version, "info"),
        badge(meta.parser || "parser ?"),
        badge(result.source === "on-the-fly" ? "computed on the fly" : result.source, result.source === "on-the-fly" ? "warn" : null),
        el("span", { cls: "muted", text: `${fmtValue(meta.processing_ms)} ms · rules ${(meta.rules_hash || "").slice(0, 12)}` })),
      (meta.errors || []).length ? el("div", { cls: "error-box" }, el("ul", {}, meta.errors.map((e) => el("li", { text: e })))) : null,
      (meta.warnings || []).length ? el("p", { cls: "note", text: "Note: " + meta.warnings.join(" · ") }) : null,
      el("p", { cls: "muted", text: "Static analysis only: scripts are parsed, never run. External <script src> files are not downloaded. Part 7 reports API usage; intent is decided in Part 8." }));

    // Summary: counts, then one chip per category (page-own code only).
    const own = summary.categories_page_own || {};
    const lib = summary.categories_library || {};
    const categories = Array.from(new Set(Object.keys(own).concat(Object.keys(lib))));
    const flags = Object.entries(summary.flags || {}).filter(([, v]) => v).map(([k]) => k);
    fill(box, section("Summary",
      el("div", { cls: "cards" },
        countCard("scripts analysed", summary.scripts_analyzed),
        countCard("lexical fallback", summary.scripts_lexical),
        countCard("library scripts", summary.library_scripts, (summary.libraries || []).join(", ")),
        countCard("detections (page-own)", summary.detections_page_own, `of ${fmtInt(summary.detections_total)} total`),
        countCard("external scripts", (r.external_scripts || []).length)),
      el("h3", { cls: "heading" }, "API categories (page-own · library)"),
      categories.length
        ? el("div", { cls: "toolbar" }, categories.map((c) =>
          badge(`${c}: ${fmtInt(own[c] || 0)}${lib[c] ? ` · lib ${fmtInt(lib[c])}` : ""}`, own[c] ? JS_CATEGORY_KIND[c] || "info" : null)))
        : el("p", { cls: "muted", text: "No API usage found." }),
      el("h3", { cls: "heading" }, "Flags (page-own)"),
      flags.length ? el("div", { cls: "toolbar" }, flags.map((f) => badge(f, "warn"))) : el("p", { cls: "muted", text: "None." })));

    // Detections table with two filters (library code, category).
    const tableBox = el("div");
    const showLib = el("input", { attrs: { type: "checkbox" } });
    const category = el("select", {}, el("option", { text: "all categories", attrs: { value: "" } }),
      ...categories.map((c) => el("option", { text: c, attrs: { value: c } })));
    const draw = () => {
      const rows = detections.filter((d) => (showLib.checked || !d.in_library) && (!category.value || d.category === category.value));
      fill(clear(tableBox), table(["api", "source", "line", "access", "snippet (text only)", "URL / literal", "where / confidence"],
        rows, (d) => detectionRow(d, scripts), 200));
    };
    showLib.addEventListener("change", draw);
    category.addEventListener("change", draw);
    const cut = summary.detections_stored !== undefined && summary.detections_stored < summary.detections_total;
    fill(box, section(`Detections (${fmtInt(detections.length)})`,
      el("div", { cls: "toolbar" }, el("label", { cls: "row" }, showLib, " include library code"), category,
        cut ? badge(`list cut at ${fmtInt(summary.detections_stored)}`, "warn") : null),
      tableBox));
    draw();

    // One card per analysed piece of JavaScript, with its obfuscation statistics.
    const cards = el("div");
    cards.hidden = scripts.length > 12;
    const toggle = el("button", { attrs: { type: "button" }, text: cards.hidden ? `Show all ${scripts.length} scripts` : "Hide scripts" });
    toggle.addEventListener("click", () => {
      if (!cards.firstChild) cards.append(...scripts.map(scriptCard));
      cards.hidden = !cards.hidden;
      toggle.textContent = cards.hidden ? `Show all ${scripts.length} scripts` : "Hide scripts";
    });
    if (!cards.hidden) cards.append(...scripts.map(scriptCard));
    fill(box, section(`Scripts (${scripts.length}) - obfuscation statistics are descriptive (minified ≠ obfuscated)`, toggle, cards));

    fill(box, section(`External scripts (${(r.external_scripts || []).length}) - address only, never downloaded`,
      table(["src", "domain", "site", "CDN / library", "flags", "async / defer", "integrity"], r.external_scripts || [], (s) => [
        urlText(s.src), s.domain,
        s.is_external ? badge("third-party", "warn") : badge("same site", "ok"),
        el("span", {}, s.known_cdn ? badge("known CDN", "ok") : null, " ", s.library ? badge(s.library, "info") : null),
        el("span", {}, ...(s.flags || []).map((f) => badge(f, f === "insecure_http" ? "warn" : "danger"))),
        [s.async ? "async" : "", s.defer ? "defer" : ""].filter(Boolean).join(" ") || "—",
        yes(s.has_integrity, "ok"),
      ])));

    fill(box, section("Limitations (static mode)", el("ul", {}, (r.limitations || []).map((x) => el("li", { text: x })))));
  },
});

// ---- 9. Behavior (Part 8) ---------------------------------------------------
// What the page's code is TRYING TO DO: sources -> flows -> sinks, patterns with
// severity and the evidence chain (source line -> assignments -> sink line).
// Evidence lines are page code: shown ONLY as text (textContent, monospace).

const behaviorCache = new WeakMap();
const SEVERITY_BADGE = { critical: "danger", high: "danger", medium: "warn", low: "info" };

function behaviorResult(ctx) {
  return cached(behaviorCache, ctx, () => {
    if (ctx.kind === "sample") {
      return api(`/api/v1/dev/samples/${encodeURIComponent(ctx.sampleId)}/behavior` + query({ version: ctx.version }))
        .then((r) => ({ data: r.data, source: r.headers.get("X-Behavior-Source") || "stored" }));
    }
    return api("/api/v1/behavior", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ html: ctx.html || "", url: ctx.url || null }),
    }).then((r) => ({ data: r.data, source: "api" }));
  });
}

function riskGauge(score) {
  const value = typeof score === "number" ? Math.max(0, Math.min(100, score)) : 0;
  const kind = value >= 50 ? "danger" : value >= 25 ? "warn" : value > 0 ? "info" : "ok";
  const fillBar = el("div", { cls: "gauge-fill " + kind });
  fillBar.style.width = value.toFixed(0) + "%"; // a number, not page data
  return el("div", { cls: "gauge-wrap" },
    el("div", { cls: "gauge" }, fillBar),
    el("span", { cls: "gauge-num", text: `${value.toFixed(0)} / 100` }),
    el("span", { cls: "muted", text: "behavior risk score (descriptive: sum of each pattern's highest severity, capped - not the verdict)" }));
}

function evidenceChain(items) {
  if (!items || !items.length) return el("p", { cls: "muted", text: "No evidence lines." });
  return el("ol", { cls: "chain" }, items.map((item) => {
    const where = item.kind === "html" ? "HTML"
      : item.line ? `script ${show(item.script_index)} · line ${item.line}` : `script ${show(item.script_index)}`;
    return el("li", {},
      el("span", { cls: "where", text: where }),
      item.note ? el("span", { cls: "step-note", text: item.note }) : null,
      el("code", { cls: "step-code", text: show(item.code) }));
  }));
}

function findingCard(f) {
  return el("div", { cls: `card finding sev-${f.severity}` },
    el("h3", {},
      badge(f.severity.toUpperCase(), SEVERITY_BADGE[f.severity]),
      el("span", { text: f.name }),
      badge(f.variant),
      badge(`confidence ${f.confidence}`, f.confidence === "high" ? "ok" : f.confidence === "medium" ? "info" : "warn"),
      f.count > 1 ? badge(`×${f.count}`) : null,
      f.script_index !== null && f.script_index !== undefined ? badge(`script ${f.script_index}`) : null),
    el("p", { cls: "finding-msg", text: f.message }),
    (f.factors || []).length ? el("ul", { cls: "factors" }, f.factors.map((x) => el("li", { text: x }))) : null,
    el("div", { cls: "muted", text: "Evidence chain (follow the data):" }),
    evidenceChain(f.evidence));
}

registerTab({
  id: "behavior",
  title: "Behavior (Part 8)",
  async render(ctx, box) {
    fill(box, el("p", { cls: "muted", text: "Mapping sources to sinks (static taint analysis, nothing is executed)…" }));
    const result = await behaviorResult(ctx);
    if (state.ctx !== ctx || !box.isConnected) return; // the user moved on meanwhile
    const r = result.data;
    const meta = r.meta || {};
    const summary = r.summary || {};
    const findings = r.findings || [];
    const flows = r.flows || [];
    clear(box);

    fill(box,
      el("div", { cls: "toolbar" },
        badge(r.feature_set_version, "info"),
        badge(result.source === "on-the-fly" ? "computed on the fly" : result.source, result.source === "on-the-fly" ? "warn" : null),
        meta.truncated ? badge("truncated (a cap was hit)", "warn") : null,
        el("span", { cls: "muted", text: `${fmtValue(meta.processing_ms)} ms · rules ${(meta.rules_hash || "").slice(0, 12)} · ${fmtInt(summary.passes)} pass(es)` })),
      (r.errors || []).length ? el("div", { cls: "error-box" }, el("ul", {}, r.errors.map((e) => el("li", { text: e })))) : null,
      (meta.warnings || []).length ? el("p", { cls: "note", text: "Note: " + meta.warnings.join(" · ") }) : null,
      riskGauge(r.behavior_risk_score));

    fill(box, section("Summary",
      el("div", { cls: "cards" },
        countCard("findings", findings.length, Object.entries(summary.findings_by_severity || {}).map(([k, v]) => `${k} ${v}`).join(" · ")),
        countCard("flows", summary.flows_total),
        countCard("sources", summary.sources_total),
        countCard("sinks", summary.sinks_total),
        countCard("scripts (AST)", summary.scripts_analyzed, `${fmtInt(summary.scripts_lexical)} regex-only · ${fmtInt(summary.library_scripts_skipped)} library skipped`)),
      el("h3", { cls: "heading" }, "Sources found"),
      Object.keys(summary.sources_by_id || {}).length
        ? el("div", { cls: "toolbar" }, Object.entries(summary.sources_by_id).map(([k, v]) => badge(`${k}: ${fmtInt(v)}`)))
        : el("p", { cls: "muted", text: "None." }),
      el("h3", { cls: "heading" }, "Sinks found"),
      Object.keys(summary.sinks_by_id || {}).length
        ? el("div", { cls: "toolbar" }, Object.entries(summary.sinks_by_id).map(([k, v]) => badge(`${k}: ${fmtInt(v)}`, k.endsWith("external") ? "warn" : null)))
        : el("p", { cls: "muted", text: "None." })));

    fill(box, section(`Findings (${findings.length}) - most severe first`,
      findings.length ? findings.map(findingCard)
        : el("p", { cls: "muted", text: "No behavioral pattern found (single API calls are never a pattern on their own)." })));

    fill(box, section(`Flows (${flows.length}) - source → sink`,
      table(["#", "source", "sink", "destination", "steps", "confidence", "flags"], flows, (f) => [
        `#${f.id}`, f.source_id,
        el("span", {}, el("strong", { text: f.sink_id }), " ", el("span", { cls: "muted", text: f.sink_api })),
        f.known_endpoint ? el("span", {}, badge(f.known_endpoint, "danger"), " ", codeText(f.sink_url_domain))
          : f.sink_url_domain ? el("span", {}, codeText(f.sink_url_domain), " ", f.sink_is_external ? badge("external", "danger") : badge("same site", "ok"))
            : el("span", { cls: "muted", text: f.sink_is_external === null ? "built at run time" : "—" }),
        el("details", {}, el("summary", { text: `${f.path.length} steps` }),
          evidenceChain(f.path.map((s) => ({ kind: "flow_step", script_index: s.script_index, line: s.line, code: s.code, note: s.step + (s.note ? `: ${s.note}` : "") })))),
        badge(f.confidence, f.confidence === "high" ? "ok" : f.confidence === "medium" ? "info" : "warn"),
        el("span", {}, f.encoded ? badge(`encoded ${f.encodings.join("/")}`, "warn") : null, " ",
          f.via_function ? badge("via function") : null, " ", f.truncated ? badge("cut", "warn") : null),
      ], 100)));

    const vector = Object.entries(r.intent_vector || {});
    const nonZero = vector.filter(([, v]) => v);
    const vectorBox = el("div");
    const all = el("input", { attrs: { type: "checkbox" } });
    const drawVector = () => fill(clear(vectorBox), table(["feature", "value"], all.checked ? vector : nonZero, ([k, v]) => [codeText(k), fmtValue(v)], 100));
    all.addEventListener("change", drawVector);
    fill(box, section(`Intent vector (${vector.length} features, ${nonZero.length} non-zero)`,
      el("label", { cls: "row" }, all, " show all features"), vectorBox));
    drawVector();

    fill(box, section(`Sinks (${(r.sinks_found || []).length}) - with who triggers them`,
      table(["sink", "api", "line", "destination", "trigger", "code (text only)"], r.sinks_found || [], (s) => [
        s.sink_id, s.api, s.script_index >= 0 ? `#${s.script_index} ${s.line}:${s.column}` : "HTML",
        s.url_domain ? codeText(s.url_domain) : el("span", { cls: "muted", text: "—" }),
        el("span", {}, badge(s.trigger, s.trigger === "auto" ? "warn" : s.trigger === "user" ? "ok" : null), " ", el("span", { cls: "muted", text: show(s.trigger_reason) })),
        codeText(s.code),
      ], 100)));

    fill(box, section("Limitations (static analysis)", el("ul", {}, (r.limitations || []).map((x) => el("li", { text: x })))));
  },
});

// ---- 10. Content (Part 5) ---------------------------------------------------
// The page's TEXT as Part 6 will read it: segments per field with a language
// chip each, the CTA list, and page_text. Segment texts are page content: shown
// ONLY through el()/textContent (Sinhala/Tamil fonts come from --text-font).

const contentCache = new WeakMap();
const SCRIPT_NAMES = { si: "Sinhala", ta: "Tamil", latin: "Latin", other: "other" };
const FIELD_TITLES = [
  ["title", "Title"], ["meta_description", "Meta description"], ["heading", "Headings"],
  ["cta", "Buttons / CTAs"], ["form_label", "Form labels"], ["placeholder", "Placeholders"],
  ["alert_banner", "Alert banners"], ["paragraph", "Paragraphs"], ["visible_other", "Other visible text"],
  ["hidden", "Hidden text (not seen by the visitor)"],
];

function contentResult(ctx) {
  return cached(contentCache, ctx, () => {
    if (ctx.kind === "sample") {
      return api(`/api/v1/dev/samples/${encodeURIComponent(ctx.sampleId)}/content` + query({ version: ctx.version }))
        .then((r) => ({ data: r.data, source: r.headers.get("X-Content-Source") || "stored" }));
    }
    return api("/api/v1/content", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ html: ctx.html || "", url: ctx.url || null }),
    }).then((r) => ({ data: r.data, source: "api" }));
  });
}

const langChip = (lang, confidence, method) =>
  el("span", { cls: "lang-chip " + (lang || "unknown"), text: show(lang), title: `confidence ${fmtValue(confidence)} · ${show(method)}` });

function scriptBar(ratios) {
  const bar = el("div", { cls: "script-bar" });
  const legend = el("div", { cls: "script-legend" });
  for (const code of Object.keys(SCRIPT_NAMES)) {
    const share = Number((ratios || {})[code]) || 0;
    if (share > 0) {
      const part = el("div", { cls: "s-" + code, title: `${SCRIPT_NAMES[code]} ${(share * 100).toFixed(1)}%` });
      part.style.width = (share * 100).toFixed(2) + "%"; // a number, not page data
      bar.append(part);
    }
    legend.append(el("span", {}, el("span", { cls: "sw s-" + code }), `${SCRIPT_NAMES[code]} ${(share * 100).toFixed(1)}%`));
  }
  return el("div", {}, bar, legend);
}

function segmentLine(s) {
  return el("div", { cls: "seg" },
    el("span", { cls: "sid", text: s.segment_id }),
    langChip(s.language, s.lang_confidence, s.lang_method),
    s.level ? badge("h" + s.level) : null,
    s.count > 1 ? badge(`×${s.count}`) : null,
    el("span", { cls: "multi", text: s.text }));
}

registerTab({
  id: "content",
  title: "Content (Part 5)",
  async render(ctx, box) {
    fill(box, el("p", { cls: "muted", text: "Extracting text segments and identifying languages…" }));
    const result = await contentResult(ctx);
    if (state.ctx !== ctx || !box.isConnected) return; // the user moved on meanwhile
    const r = result.data;
    const meta = r.meta || {};
    const lang = r.language || {};
    const segments = r.segments || [];
    clear(box);

    fill(box,
      el("div", { cls: "toolbar" },
        badge(meta.schema_version || "text_v1", "info"),
        badge(result.source === "on-the-fly" ? "computed on the fly" : result.source, result.source === "on-the-fly" ? "warn" : null),
        badge(`CTAs from ${show(meta.cta_source)}`, meta.cta_source === "html" ? null : "warn"),
        meta.truncated ? badge("capped: " + (meta.truncation_reasons || []).join(", "), "warn") : null,
        el("span", { cls: "muted", text: `${fmtValue(meta.processing_ms)} ms · rules ${(meta.rules_hash || "").slice(0, 12)} · language backend ${show(lang.backend)}` })),
      (meta.errors || []).length ? el("div", { cls: "error-box" }, el("ul", {}, meta.errors.map((e) => el("li", { text: e })))) : null,
      (meta.warnings || []).length ? el("p", { cls: "note", text: "Note: " + meta.warnings.join(" · ") }) : null);

    fill(box, section("Page language",
      el("div", { cls: "toolbar" },
        el("span", { cls: "lang-chip " + (lang.language || "unknown"), text: show(lang.language) }),
        el("strong", { text: `confidence ${fmtValue(lang.confidence)}` }),
        badge(`method: ${show(lang.method)}`),
        lang.lang_attr ? el("span", { cls: "muted", text: `<html lang> says ${lang.lang_attr} (hint only)` }) : null,
        ctx.language ? el("span", { cls: "muted", text: `metadata says ${ctx.language}` }) : null),
      el("h3", { cls: "heading", text: "Script ratio (letters)" }),
      scriptBar(lang.script_ratios),
      el("h3", { cls: "heading", text: "Language share (characters of visible segments)" }),
      bars(Object.entries(lang.shares || {}).sort((a, b) => b[1] - a[1]), (v) => (v * 100).toFixed(1) + "%"),
      ["si_latn", "ta_latn"].includes(lang.language)
        ? el("p", { cls: "note", text: "Romanized Sinhala / Tamil (Singlish / Tanglish): known gap - XLM-R handles it poorly." })
        : null));

    const ctas = segments.filter((s) => s.field === "cta");
    fill(box, section(`CTAs (${ctas.length}) - buttons and action links`,
      ctas.length
        ? el("ul", { cls: "cta-list" }, ctas.map((s) => el("li", {}, langChip(s.language, s.lang_confidence, s.lang_method), " ", el("span", { cls: "multi", text: s.text }))))
        : el("p", { cls: "muted", text: "No CTA found." })));

    const counts = r.counts || {};
    fill(box, section(`Segments (${segments.length}) by field`,
      el("div", { cls: "cards" },
        countCard("visible chars", r.chars),
        countCard("segments", segments.length),
        countCard("dropped", Object.values(meta.dropped || {}).reduce((a, b) => a + b, 0),
          Object.entries(meta.dropped || {}).map(([k, v]) => `${k} ${v}`).join(" · "))),
      FIELD_TITLES.filter(([field]) => counts[field]).map(([field, title]) =>
        el("details", { attrs: { open: field !== "hidden" && field !== "visible_other" } },
          el("summary", { text: `${title} (${counts[field]})` }),
          segments.filter((s) => s.field === field).map(segmentLine))),
      r.empty ? el("p", { cls: "muted", text: "This page has no visible text." }) : null));

    fill(box, section(`page_text - model input for Part 6 (${fmtInt(r.page_text_chars)} chars${r.page_text_truncated ? ", truncated" : ""})`,
      el("pre", { text: r.page_text || "(empty)" })));
  },
});

// ---- Future parts (disabled placeholders) -------------------------------------------------

for (const [id, title] of [
  ["nlp", "XLM-R / NLP (Part 6)"],
  ["unified", "Unified Result (Part 9)"],
]) {
  registerTab({ id, title, enabled: false, render() {} });
}

// ---------------------------------------------------------------------------
// Rendering the tabs and the page header
// ---------------------------------------------------------------------------

function renderTabs() {
  const nav = clear($("tabs"));
  for (const tab of TABS) {
    const usable = tab.enabled && state.ctx && tab.available(state.ctx);
    const button = el("button", {
      cls: tab.enabled ? "" : "future",
      text: tab.title,
      title: tab.enabled ? (usable || !state.ctx ? "" : "Not available for this page") : "Coming in a later part",
      attrs: { type: "button", role: "tab", "aria-selected": String(tab.id === state.activeTab), disabled: !usable },
      onClick: () => selectTab(tab.id),
    });
    nav.append(button);
  }
}

function renderPanel() {
  const panel = clear($("panel"));
  if (!state.ctx) {
    panel.append(el("p", { cls: "empty", text: "Nothing selected yet." }));
    return;
  }
  let tab = TABS.find((t) => t.id === state.activeTab);
  if (!tab || !tab.enabled || !tab.available(state.ctx)) tab = TABS[0];
  state.activeTab = tab.id;
  // A broken tab must not break the inspector (same idea as Part 2's isolated steps).
  // render() may be async (tabs that fetch more data return a Promise).
  const failed = (error) => {
    console.error(error);
    panel.append(el("div", { cls: "error-box", text: `This tab failed to render: ${error.message}` }));
  };
  try {
    const pending = tab.render(state.ctx, panel);
    if (pending && typeof pending.catch === "function") pending.catch(failed);
  } catch (error) {
    failed(error);
  }
}

function renderHeader() {
  const header = clear($("page-header"));
  const c = state.ctx;
  if (!c) {
    fill(header, el("span", { cls: "muted", text: "Pick a sample on the left, or paste HTML above." }));
    return;
  }
  fill(header, 
    c.label ? labelChip(c.label) : badge("pasted HTML", "info"),
    c.sampleId ? badge(c.sampleId) : null,
    c.version ? badge(c.version) : null,
    el("span", { cls: "title multi", text: c.page.title || "(no title)" }),
    c.parsedSource === "on-the-fly" ? badge("processed on the fly", "warn") : null,
  );
}

function selectTab(id) {
  state.activeTab = id;
  renderTabs();
  renderPanel();
  writeHash();
}

function showPage(ctx) {
  state.ctx = ctx;
  renderHeader();
  renderTabs();
  renderPanel();
  writeHash();
}

// ---------------------------------------------------------------------------
// URL hash: #v=v0.1&sample=c2_phishing_000012&tab=forms  (deep links for demos)
// ---------------------------------------------------------------------------

function writeHash() {
  const params = new URLSearchParams();
  const version = $("version-select").value;
  if (version) params.set("v", version);
  if (state.ctx && state.ctx.kind === "sample") params.set("sample", state.ctx.sampleId);
  params.set("tab", state.activeTab);
  history.replaceState(null, "", "#" + params.toString());
}

function readHash() {
  const params = new URLSearchParams(location.hash.slice(1));
  const tab = params.get("tab");
  return {
    version: VERSION.test(params.get("v") || "") ? params.get("v") : null,
    sample: SAMPLE_ID.test(params.get("sample") || "") ? params.get("sample") : null,
    tab: TABS.some((t) => t.id === tab && t.enabled) ? tab : null,
  };
}

// ---------------------------------------------------------------------------
// Sidebar: versions, filters, sample list
// ---------------------------------------------------------------------------

function setStatus(text, isError) {
  const status = $("status");
  status.textContent = text || "";
  status.classList.toggle("error", Boolean(isError));
}

async function loadVersions(preferred) {
  const select = $("version-select");
  try {
    const { data } = await api("/api/v1/dev/versions");
    state.versions = data;
    clear(select);
    for (const v of data) select.append(el("option", { text: v.version, attrs: { value: v.version } }));
    if (!data.length) {
      $("version-info").textContent = "No frozen dataset version - paste HTML above instead.";
      return false;
    }
    if (preferred && data.some((v) => v.version === preferred)) select.value = preferred;
    updateVersionInfo();
    return true;
  } catch (error) {
    $("version-info").textContent = "Could not load versions: " + error.message;
    return false;
  }
}

function updateVersionInfo() {
  const v = state.versions.find((x) => x.version === $("version-select").value);
  if (!v) return;
  $("version-info").textContent = `${fmtInt(v.total)} samples · ${fmtInt(v.processed)} processed by Part 2` + (v.created_at ? ` · frozen ${v.created_at.slice(0, 10)}` : "");
  $("version-info").title = v.notes || "";
  const fill = (select, counts, allText) => {
    const current = select.value;
    clear(select).append(el("option", { text: allText, attrs: { value: "" } }));
    for (const [name, n] of Object.entries(counts || {})) {
      select.append(el("option", { text: `${name} (${n})`, attrs: { value: name, disabled: n === 0 } }));
    }
    select.value = Object.prototype.hasOwnProperty.call(counts || {}, current) ? current : "";
  };
  fill($("label-filter"), v.counts_per_label, "All labels");
  fill($("language-filter"), v.counts_per_language, "All languages");
}

async function loadSamples() {
  const token = ++state.loadToken;
  const list = clear($("sample-list"));
  const version = $("version-select").value;
  if (!version) return;
  $("sample-count").textContent = "Loading…";
  try {
    const { data } = await api("/api/v1/dev/samples" + query({
      version,
      label: $("label-filter").value,
      language: $("language-filter").value,
      q: $("search-input").value.trim(),
      has_password: $("password-filter").checked ? "true" : "",
      external_form_action: $("external-filter").checked ? "true" : "",
      misclassified: $("misclassified-filter").checked ? "true" : "",
      has_critical_behavior: $("critical-filter").checked ? "true" : "",
    }));
    if (token !== state.loadToken) return; // a newer filter change is already loading
    state.samples = data;
    $("sample-count").textContent = `${fmtInt(data.length)} sample(s)`;
    for (const s of data) list.append(sampleItem(s));
  } catch (error) {
    if (token === state.loadToken) $("sample-count").textContent = "Error: " + error.message;
  }
}

function sampleItem(s) {
  const current = state.ctx && state.ctx.kind === "sample" && state.ctx.sampleId === s.sample_id;
  const button = el("button", {
    attrs: { type: "button", "aria-current": String(Boolean(current)), "data-id": s.sample_id },
    title: s.title || s.sample_id,
    onClick: () => openSample(s.sample_id),
  },
  labelChip(s.label),
  el("span", { cls: "t multi", text: s.title || "(no title)" }),
  el("span", { cls: "sub" }, el("span", { text: s.sample_id }), el("span", { text: s.language }),
    s.has_password ? badge("password", "warn") : null,
    s.external_form_action ? badge("ext form", "danger") : null,
    s.misclassified ? badge("misclassified", "danger") : null,
    s.behavior_max_severity === "critical" || s.behavior_max_severity === "high"
      ? badge(`behavior ${s.behavior_max_severity}`, "danger") : null,
    s.processed ? null : badge("not processed")));
  return el("li", {}, button);
}

function markCurrent() {
  for (const b of $("sample-list").querySelectorAll("button[data-id]")) {
    b.setAttribute("aria-current", String(Boolean(state.ctx && state.ctx.kind === "sample" && b.dataset.id === state.ctx.sampleId)));
  }
}

async function openSample(sampleId) {
  if (!SAMPLE_ID.test(sampleId)) return;
  const version = $("version-select").value;
  const meta = state.samples.find((s) => s.sample_id === sampleId) || {};
  setStatus(`Loading ${sampleId}…`);
  try {
    const { data, headers } = await api(`/api/v1/dev/samples/${encodeURIComponent(sampleId)}/parsed` + query({ version }));
    showPage({
      page: data, kind: "sample", sampleId, version,
      label: meta.label, language: meta.language,
      parsedSource: headers.get("X-Parsed-Source") || "stored",
    });
    markCurrent();
    setStatus(`${sampleId} loaded (${headers.get("X-Parsed-Source") || "stored"}).`);
  } catch (error) {
    setStatus(`Could not load ${sampleId}: ${error.message}`, true);
  }
}

// Up/Down arrows move through the sample list (handy during demos).
function listKeys(event) {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  const buttons = [...$("sample-list").querySelectorAll("button[data-id]")];
  const index = buttons.indexOf(document.activeElement);
  if (index < 0) return;
  event.preventDefault();
  const next = buttons[index + (event.key === "ArrowDown" ? 1 : -1)];
  if (next) {
    next.focus();
    next.click();
  }
}

// ---------------------------------------------------------------------------
// Top bar: analyze pasted HTML / a local file (read as text, never rendered)
// ---------------------------------------------------------------------------

async function analyzePasted(event) {
  event.preventDefault();
  const html = $("html-input").value;
  const url = $("url-input").value.trim();
  if (!html.trim()) {
    setStatus("Paste some HTML (or choose a file) first.", true);
    return;
  }
  const body = JSON.stringify({ html, url: url || null });
  if (new Blob([body]).size > MAX_HTML_BYTES) {
    setStatus("Too large: the API accepts at most 5 MB.", true);
    return;
  }
  $("analyze-btn").disabled = true;
  setStatus("Analyzing…");
  try {
    const { data } = await api("/api/v1/preprocess", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    // html/url are kept (as strings, never rendered) so later tabs can send them to
    // their own endpoints, e.g. DOM Features -> POST /api/v1/dom-features.
    showPage({ page: data, kind: "pasted", parsedSource: "api", html, url: url || null });
    markCurrent();
    setStatus(`Analyzed ${fmtBytes(data.meta && data.meta.html_size_bytes)} in ${show(data.meta && data.meta.processing_ms)} ms (POST /api/v1/preprocess).`);
  } catch (error) {
    setStatus(error.status === 413 ? "Too large: the API accepts at most 5 MB." : "Analyze failed: " + error.message, true);
  } finally {
    $("analyze-btn").disabled = false;
  }
}

function loadFile() {
  const file = $("file-input").files[0];
  if (!file) return;
  if (file.size > MAX_HTML_BYTES) {
    setStatus(`${file.name} is ${fmtBytes(file.size)} - the API accepts at most 5 MB.`, true);
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    $("html-input").value = String(reader.result); // shown as text in a textarea, never rendered
    setStatus(`${file.name} loaded (${fmtBytes(file.size)}) - press Analyze.`);
  };
  reader.onerror = () => setStatus(`Could not read ${file.name}.`, true);
  reader.readAsText(file);
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

function debounce(fn, ms) {
  let timer = null;
  return () => {
    clearTimeout(timer);
    timer = setTimeout(fn, ms);
  };
}

async function start() {
  const initial = readHash();
  if (initial.tab) state.activeTab = initial.tab;
  renderTabs();
  renderPanel();

  $("analyze-form").addEventListener("submit", analyzePasted);
  $("file-input").addEventListener("change", loadFile);
  $("clear-btn").addEventListener("click", () => {
    $("html-input").value = "";
    $("url-input").value = "";
    $("file-input").value = "";
    setStatus("");
  });
  $("version-select").addEventListener("change", () => {
    updateVersionInfo();
    loadSamples();
    writeHash();
  });
  for (const id of ["label-filter", "language-filter", "password-filter", "external-filter", "misclassified-filter", "critical-filter"]) {
    $(id).addEventListener("change", loadSamples);
  }
  $("search-input").addEventListener("input", debounce(loadSamples, 250));
  $("sample-list").addEventListener("keydown", listKeys);

  if (await loadVersions(initial.version)) {
    await loadSamples();
    if (initial.sample) await openSample(initial.sample);
  }
}

document.addEventListener("DOMContentLoaded", start);
