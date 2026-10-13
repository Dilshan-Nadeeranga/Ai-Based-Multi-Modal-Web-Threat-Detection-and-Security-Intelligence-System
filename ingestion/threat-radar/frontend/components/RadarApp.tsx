"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import WatchPosts from "./WatchPosts";

type SavedFile = { name: string; bytes: number; modified: string };
type Account = { account?: { license_name?: string; email?: string; status?: string } };
type ScrapedRow = { domain?: string; channel: string; date: string; url: string; views?: string; has_photo?: string };
type RedditRow = { domain?: string; subreddit: string; date: string; url: string; score?: string; title?: string; post_id?: string };
type RedditPost = {
  post_id: string; subreddit: string; date: string; matched_keywords: string;
  title: string; text: string; post_url: string; urls: string[]; image_urls: string[]; image_files: string[];
};
type AuthStep = "none" | "code_sent" | "password_needed" | "done" | "error";
type AuthStatus = { success: boolean; step: AuthStep; name?: string; phone?: string; username?: string | null; message?: string };
type RedditAuthStatus = { success: boolean; step: AuthStep | "browser_open"; username?: string; message?: string };

type FilteredDomain = {
  domain: string;
  reasons: string[];
  matchedKeywords: string[];
  mimicBrand?: string;
  mimicType?: string;
};

export default function HomePage() {
  // ── domain downloader state ──────────────────────────────────
  const [zone, setZone] = useState("dailyupdate");
  const [format, setFormat] = useState("text");
  const [useFeed, setUseFeed] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [files, setFiles] = useState<SavedFile[]>([]);
  const [account, setAccount] = useState<Account | null>(null);

  // ── domain filter state (domains-monitor lists only) ───────────
  const [domainKeywords, setDomainKeywords] = useState<string[]>([]);
  const [newDomainKeyword, setNewDomainKeyword] = useState("");
  const [domainKwMsg, setDomainKwMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [filteredDomains, setFilteredDomains] = useState<FilteredDomain[]>([]);
  const [filteredMeta, setFilteredMeta] = useState<{
    matchedCount: number;
    totalScanned: number;
    sourceFile?: string;
    filteredAt?: string;
    savedFile?: string;
  } | null>(null);
  const [filterLoading, setFilterLoading] = useState(false);

  // ── telegram auth state ───────────────────────────────────────
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [authPhone, setAuthPhone] = useState("");
  const [authCode, setAuthCode] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authLoading, setAuthLoading] = useState(false);
  const [authMsg, setAuthMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  // ── reddit auth state ─────────────────────────────────────────
  const [redditAuthStatus, setRedditAuthStatus] = useState<RedditAuthStatus | null>(null);
  const [redditUsername, setRedditUsername] = useState("");
  const [redditPassword, setRedditPassword] = useState("");
  const [redditAuthLoading, setRedditAuthLoading] = useState(false);
  const [redditAuthMsg, setRedditAuthMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [redditSessionJson, setRedditSessionJson] = useState("");
  const [showRedditImport, setShowRedditImport] = useState(false);
  const [redditBrowserLogin, setRedditBrowserLogin] = useState(true);
  const [redditCredentialLogin, setRedditCredentialLogin] = useState(true);
  const [redditPlaywrightReady, setRedditPlaywrightReady] = useState(false);
  const [redditCloudBackend, setRedditCloudBackend] = useState(false);
  const redditBrowserPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── keyword scraper state ─────────────────────────────────────
  const [keywords, setKeywords] = useState<string[]>([]);
  const [newKeyword, setNewKeyword] = useState("");
  const [kwMsg, setKwMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [scrapedRows, setScrapedRows] = useState<ScrapedRow[]>([]);
  const [scrapedMeta, setScrapedMeta] = useState<{
    lastModified: string | null;
    count: number;
    today?: string;
    seenDomainsTotal?: number;
  } | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── reddit scraper state ──────────────────────────────────────
  const [subreddits, setSubreddits] = useState<string[]>([]);
  const [newSubreddit, setNewSubreddit] = useState("");
  const [redditMsg, setRedditMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [redditRows, setRedditRows] = useState<RedditRow[]>([]);
  const [redditPosts, setRedditPosts] = useState<RedditPost[]>([]);
  const [redditMeta, setRedditMeta] = useState<{ lastModified: string | null; count: number } | null>(null);
  const [redditAutoScrape, setRedditAutoScrape] = useState(false);
  const [redditScraperRunning, setRedditScraperRunning] = useState(false);
  const [redditSearchScope, setRedditSearchScope] = useState<"global" | "subreddits" | "both">("global");
  const [redditPollInterval, setRedditPollInterval] = useState(300);
  const redditPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const path = usePathname();
  const onSetup = path.startsWith("/setup");
  const onWatch = path.startsWith("/watch");
  const onDash = !onSetup && !onWatch;
  const [clock, setClock] = useState("");

  // ── loaders ───────────────────────────────────────────────────
  const loadAuthStatus = useCallback(async () => {
    try {
      const r = await fetch("/api/auth/status");
      if (r.ok) {
        setAuthStatus(await r.json());
      } else {
        setAuthStatus({
          success: false,
          step: "error",
          message: `Backend returned ${r.status}. Check BACKEND_URL / Render service.`,
        });
      }
    } catch {
      setAuthStatus({
        success: false,
        step: "error",
        message: "Cannot reach backend API",
      });
    }
  }, []);

  const loadFiles = useCallback(async () => {
    try {
      const r = await fetch("/api/downloads");
      if (r.ok) {
        const data = await r.json();
        setFiles(data.files ?? []);
      }
    } catch { /* backend offline */ }
  }, []);

  const loadAccount = useCallback(async () => {
    try {
      const r = await fetch("/api/account");
      if (r.ok) setAccount(await r.json());
    } catch { /* ignore */ }
  }, []);

  const loadKeywords = useCallback(async () => {
    try {
      const r = await fetch("/api/keywords");
      if (r.ok) {
        const d = await r.json();
        setKeywords(d.keywords ?? []);
      }
    } catch { /* ignore */ }
  }, []);

  const loadDomainKeywords = useCallback(async () => {
    try {
      const r = await fetch("/api/domain-filter/keywords");
      if (r.ok) {
        const d = await r.json();
        setDomainKeywords(d.keywords ?? []);
      }
    } catch { /* ignore */ }
  }, []);

  const loadFilteredDomains = useCallback(async () => {
    try {
      const r = await fetch("/api/domain-filter/results");
      if (r.ok) {
        const d = await r.json();
        setFilteredDomains(d.domains ?? []);
        const latestFile =
          Array.isArray(d.files) && d.files.length > 0 ? d.files[0].name : undefined;
        setFilteredMeta({
          matchedCount: d.matchedCount ?? 0,
          totalScanned: d.totalScanned ?? 0,
          sourceFile: d.sourceFile,
          filteredAt: d.filteredAt,
          savedFile: latestFile,
        });
      }
    } catch { /* ignore */ }
  }, []);

  const loadScraped = useCallback(async () => {
    try {
      const r = await fetch("/api/scraper/results?limit=200");
      if (r.ok) {
        const d = await r.json();
        setScrapedRows(d.results ?? []);
        setScrapedMeta({
          lastModified: d.lastModified,
          count: d.count,
          today: d.today,
          seenDomainsTotal: d.seenDomainsTotal,
        });
      }
    } catch { /* ignore */ }
  }, []);

  const loadRedditAuthStatus = useCallback(async () => {
    try {
      const r = await fetch("/api/reddit-auth/status");
      if (r.ok) setRedditAuthStatus(await r.json());
    } catch { /* ignore */ }
  }, []);

  const loadRedditCapabilities = useCallback(async () => {
    try {
      const r = await fetch("/api/reddit-auth/capabilities");
      if (r.ok) {
        const d = await r.json();
        setRedditBrowserLogin(Boolean(d.browserLogin));
        setRedditCredentialLogin(Boolean(d.credentialLogin));
        setRedditPlaywrightReady(Boolean(d.playwrightReady));
        setRedditCloudBackend(Boolean(d.cloud));
        if (!d.browserLogin) setShowRedditImport(true);
      }
    } catch { /* ignore */ }
  }, []);

  const loadSubreddits = useCallback(async () => {
    try {
      const r = await fetch("/api/reddit/subreddits");
      if (r.ok) {
        const d = await r.json();
        setSubreddits(d.subreddits ?? []);
      }
    } catch { /* ignore */ }
  }, []);

  const loadRedditSettings = useCallback(async () => {
    try {
      const r = await fetch("/api/reddit/settings");
      if (r.ok) {
        const d = await r.json();
        setRedditAutoScrape(Boolean(d.autoScrape));
        setRedditScraperRunning(Boolean(d.running));
        if (d.searchScope === "global" || d.searchScope === "subreddits" || d.searchScope === "both") {
          setRedditSearchScope(d.searchScope);
        }
        if (typeof d.pollIntervalSeconds === "number") {
          setRedditPollInterval(d.pollIntervalSeconds);
        }
      }
    } catch { /* ignore */ }
  }, []);

  const loadRedditScraped = useCallback(async () => {
    try {
      const r = await fetch("/api/reddit/results?limit=200");
      if (r.ok) {
        const d = await r.json();
        setRedditRows(d.results ?? []);
        setRedditMeta({ lastModified: d.lastModified, count: d.count });
      }
      const posts = await fetch("/api/reddit/posts?limit=50");
      if (posts.ok) {
        const d = await posts.json();
        setRedditPosts(d.results ?? []);
      }
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    loadAuthStatus();
    loadRedditAuthStatus();
    loadRedditCapabilities();
    loadFiles();
    loadAccount();
    loadKeywords();
    loadDomainKeywords();
    loadFilteredDomains();
    loadScraped();
    loadSubreddits();
    loadRedditSettings();
    loadRedditScraped();

    // Poll scraped results every 30 s while page is open
    pollRef.current = setInterval(loadScraped, 30_000);
    redditPollRef.current = setInterval(() => {
      loadRedditScraped();
      loadRedditSettings();
    }, 30_000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      if (redditPollRef.current) clearInterval(redditPollRef.current);
      if (redditBrowserPollRef.current) clearInterval(redditBrowserPollRef.current);
    };
  }, [loadFiles, loadAccount, loadKeywords, loadDomainKeywords, loadFilteredDomains, loadScraped, loadSubreddits, loadRedditScraped, loadRedditAuthStatus, loadRedditCapabilities, loadAuthStatus, loadRedditSettings]);

  // ── telegram auth ─────────────────────────────────────────────
  async function authPost(path: string, body: Record<string, string>) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return r.json() as Promise<AuthStatus>;
  }

  async function handleRequestCode(e: React.FormEvent) {
    e.preventDefault();
    setAuthLoading(true); setAuthMsg(null);
    try {
      const d = await authPost("/api/auth/request-code", { phone: authPhone });
      setAuthStatus(d);
      if (d.success) setAuthMsg({ type: "ok", text: d.message ?? "Code sent!" });
      else setAuthMsg({ type: "err", text: d.message ?? "Failed to send code" });
    } finally { setAuthLoading(false); }
  }

  async function handleVerifyCode(e: React.FormEvent) {
    e.preventDefault();
    setAuthLoading(true); setAuthMsg(null);
    try {
      const d = await authPost("/api/auth/verify-code", { code: authCode });
      setAuthStatus(d);
      if (d.success && d.step === "done") {
        setAuthMsg({ type: "ok", text: `Logged in as ${d.name}` });
        setAuthCode("");
      } else if (d.step === "password_needed") {
        setAuthMsg({ type: "ok", text: "Enter your 2FA password below" });
      } else {
        setAuthMsg({ type: "err", text: d.message ?? "Invalid code" });
      }
    } finally { setAuthLoading(false); }
  }

  async function handleVerifyPassword(e: React.FormEvent) {
    e.preventDefault();
    setAuthLoading(true); setAuthMsg(null);
    try {
      const d = await authPost("/api/auth/verify-password", { password: authPassword });
      setAuthStatus(d);
      if (d.success) {
        setAuthMsg({ type: "ok", text: `Logged in as ${d.name}` });
        setAuthPassword("");
      } else {
        setAuthMsg({ type: "err", text: d.message ?? "Wrong password" });
      }
    } finally { setAuthLoading(false); }
  }

  async function handleLogout() {
    if (!confirm("Log out from Telegram?")) return;
    setAuthLoading(true);
    try {
      const d = await authPost("/api/auth/logout", {});
      setAuthStatus(d);
      setAuthMsg({ type: "ok", text: "Logged out" });
      setAuthPhone(""); setAuthCode(""); setAuthPassword("");
    } finally { setAuthLoading(false); }
  }

  // ── reddit auth ───────────────────────────────────────────────
  async function pollRedditBrowserLogin() {
    try {
      const r = await fetch("/api/reddit-auth/browser-login/status");
      const d = await parseApiJson(r);
      if (d.browserLogin === "done" && d.success) {
        if (redditBrowserPollRef.current) clearInterval(redditBrowserPollRef.current);
        setRedditAuthStatus(d as RedditAuthStatus);
        setRedditAuthMsg({ type: "ok", text: "Logged in to Reddit — session saved" });
        setRedditAuthLoading(false);
      } else if (d.browserLogin === "error") {
        if (redditBrowserPollRef.current) clearInterval(redditBrowserPollRef.current);
        setRedditAuthStatus({ success: false, step: "error", message: String(d.message) });
        setRedditAuthMsg({ type: "err", text: String(d.message ?? "Browser login failed") });
        setRedditAuthLoading(false);
      } else {
        setRedditAuthStatus({ success: false, step: "browser_open", message: String(d.message) });
      }
    } catch (err) {
      if (redditBrowserPollRef.current) clearInterval(redditBrowserPollRef.current);
      setRedditAuthMsg({ type: "err", text: String(err) });
      setRedditAuthLoading(false);
    }
  }

  async function handleStartRedditBrowserLogin() {
    setRedditAuthLoading(true);
    setRedditAuthMsg(null);
    try {
      const r = await fetch("/api/reddit-auth/browser-login/start", { method: "POST" });
      const d = await parseApiJson(r);
      if (!r.ok && !d.success) throw new Error(String(d.message ?? "Could not start browser login"));
      setRedditAuthStatus({ success: false, step: "browser_open", message: String(d.message) });
      setRedditAuthMsg({
        type: "ok",
        text: "Browser window opened — log in to Reddit (solve CAPTCHA if shown)",
      });
      if (redditBrowserPollRef.current) clearInterval(redditBrowserPollRef.current);
      redditBrowserPollRef.current = setInterval(pollRedditBrowserLogin, 2000);
      await pollRedditBrowserLogin();
    } catch (err) {
      setRedditAuthMsg({ type: "err", text: String(err) });
      setRedditAuthLoading(false);
    }
  }

  async function parseApiJson(r: Response) {
    const text = await r.text();
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error(
        text.startsWith("Internal")
          ? "Backend unreachable. For local dev set BACKEND_URL=http://localhost:4000 in frontend/.env and restart npm run dev."
          : text.slice(0, 200) || `Request failed (${r.status})`
      );
    }
  }

  async function handleRedditLogin(e: React.FormEvent) {
    e.preventDefault();
    setRedditAuthLoading(true);
    setRedditAuthMsg(null);
    try {
      const r = await fetch("/api/reddit-auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: redditUsername, password: redditPassword }),
      });
      const d = await parseApiJson(r);
      setRedditAuthStatus(d as RedditAuthStatus);
      if (d.success) {
        setRedditAuthMsg({ type: "ok", text: String(d.message ?? "Reddit session saved") });
        setRedditPassword("");
      } else {
        setRedditAuthMsg({ type: "err", text: String(d.message ?? "Login failed") });
      }
    } catch (err) {
      setRedditAuthMsg({ type: "err", text: String(err) });
    } finally {
      setRedditAuthLoading(false);
    }
  }

  async function handleRedditImportSession(e: React.FormEvent) {
    e.preventDefault();
    setRedditAuthLoading(true);
    setRedditAuthMsg(null);
    try {
      const data = JSON.parse(redditSessionJson);
      const r = await fetch("/api/reddit-auth/import-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const d = await r.json();
      setRedditAuthStatus(d);
      if (d.success) {
        setRedditAuthMsg({ type: "ok", text: "Session cookies imported" });
        setRedditSessionJson("");
        setShowRedditImport(false);
      } else {
        setRedditAuthMsg({ type: "err", text: d.message ?? "Import failed" });
      }
    } catch {
      setRedditAuthMsg({ type: "err", text: "Invalid JSON — paste Playwright storageState format" });
    } finally {
      setRedditAuthLoading(false);
    }
  }

  async function handleRedditLogout() {
    if (!confirm("Log out from Reddit?")) return;
    setRedditAuthLoading(true);
    try {
      const r = await fetch("/api/reddit-auth/logout", { method: "POST" });
      const d = await r.json();
      setRedditAuthStatus(d);
      setRedditAuthMsg({ type: "ok", text: "Logged out" });
      setRedditUsername("");
      setRedditPassword("");
    } finally {
      setRedditAuthLoading(false);
    }
  }

  async function handleToggleRedditScrape() {
    const next = !redditAutoScrape;
    setRedditMsg(null);
    try {
      const r = await fetch("/api/reddit/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ autoScrape: next, searchScope: redditSearchScope }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed to update scraper");
      setRedditAutoScrape(Boolean(d.autoScrape));
      setRedditScraperRunning(Boolean(d.running));
      setRedditMsg({
        type: "ok",
        text: d.autoScrape ? "Reddit auto-scrape turned ON" : "Reddit auto-scrape turned OFF",
      });
    } catch (err) {
      setRedditMsg({ type: "err", text: String(err) });
    }
  }

  async function handleRedditSearchScopeChange(scope: "global" | "subreddits" | "both") {
    setRedditSearchScope(scope);
    setRedditMsg(null);
    try {
      const r = await fetch("/api/reddit/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ searchScope: scope, autoScrape: redditAutoScrape }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed to update search scope");
      setRedditSearchScope(d.searchScope);
      setRedditMsg({ type: "ok", text: `Search mode: ${d.searchScope}` });
    } catch (err) {
      setRedditMsg({ type: "err", text: String(err) });
    }
  }

  async function handleRedditPollIntervalChange(seconds: number) {
    setRedditPollInterval(seconds);
    setRedditMsg(null);
    try {
      const r = await fetch("/api/reddit/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pollIntervalSeconds: seconds,
          autoScrape: redditAutoScrape,
          searchScope: redditSearchScope,
        }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed to update interval");
      setRedditPollInterval(d.pollIntervalSeconds);
      setRedditMsg({ type: "ok", text: `Scrape interval: every ${d.pollIntervalSeconds}s` });
    } catch (err) {
      setRedditMsg({ type: "err", text: String(err) });
    }
  }

  // ── domain download ───────────────────────────────────────────
  async function handleDownload(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setMessage(null);
    try {
      const r = await fetch("/api/download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ zone, format, useFeed }),
      });
      const contentType = r.headers.get("content-type") ?? "";
      if (!r.ok) {
        const msg = contentType.includes("application/json")
          ? ((await r.json()) as { error?: string }).error ?? "Download failed"
          : await r.text().then((t) => t.slice(0, 120));
        throw new Error(msg);
      }
      const data = await r.json();
      const extra =
        data.domainCount != null
          ? `${data.domainCount.toLocaleString()} domains`
          : data.lineCount != null
            ? `${data.lineCount.toLocaleString()} lines`
            : `${(data.bytes / 1024 / 1024).toFixed(2)} MB`;
      const filtered = data.filtered?.matchedCount;
      const filterNote =
        filtered != null
          ? ` · ${filtered.toLocaleString()} suspicious saved to filtered JSON`
          : "";
      setMessage({ type: "ok", text: `Saved ${data.saved} (${extra})${filterNote}` });
      await loadFiles();
      await loadFilteredDomains();
    } catch (err) {
      setMessage({ type: "err", text: String(err) });
    } finally {
      setLoading(false);
    }
  }

  // ── domain list filter (domains-monitor API only) ─────────────
  async function handleAddDomainKeyword(e: React.FormEvent) {
    e.preventDefault();
    const kw = newDomainKeyword.trim().toLowerCase();
    if (!kw) return;
    setDomainKwMsg(null);
    try {
      const r = await fetch("/api/domain-filter/keywords", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ keyword: kw }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed to add keyword");
      setDomainKeywords(d.keywords ?? []);
      setNewDomainKeyword("");
      setDomainKwMsg({ type: "ok", text: `"${kw}" added` });
    } catch (err) {
      setDomainKwMsg({ type: "err", text: String(err) });
    }
  }

  async function handleRemoveDomainKeyword(kw: string) {
    try {
      const r = await fetch(`/api/domain-filter/keywords/${encodeURIComponent(kw)}`, {
        method: "DELETE",
      });
      const d = await r.json();
      setDomainKeywords(d.keywords ?? []);
    } catch { /* ignore */ }
  }

  async function handleRunDomainFilter() {
    setFilterLoading(true);
    setDomainKwMsg(null);
    try {
      const r = await fetch("/api/domain-filter/run", { method: "POST" });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Filter failed");
      setDomainKwMsg({
        type: "ok",
        text: `Found ${d.matchedCount?.toLocaleString() ?? 0} suspicious of ${d.totalScanned?.toLocaleString() ?? 0} domains`,
      });
      await loadFilteredDomains();
    } catch (err) {
      setDomainKwMsg({ type: "err", text: String(err) });
    } finally {
      setFilterLoading(false);
    }
  }

  // ── keyword management ────────────────────────────────────────
  async function handleAddKeyword(e: React.FormEvent) {
    e.preventDefault();
    const kw = newKeyword.trim().toLowerCase();
    if (!kw) return;
    setKwMsg(null);
    try {
      const r = await fetch("/api/keywords", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ keyword: kw }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed to add keyword");
      setKeywords(d.keywords ?? []);
      setNewKeyword("");
      setKwMsg({ type: "ok", text: `"${kw}" added` });
    } catch (err) {
      setKwMsg({ type: "err", text: String(err) });
    }
  }

  async function handleRemoveKeyword(kw: string) {
    try {
      const r = await fetch(`/api/keywords/${encodeURIComponent(kw)}`, { method: "DELETE" });
      const d = await r.json();
      setKeywords(d.keywords ?? []);
    } catch { /* ignore */ }
  }

  async function handleClearResults() {
    if (!confirm("Clear all Telegram scraped results?")) return;
    try {
      await fetch("/api/scraper/results", { method: "DELETE" });
      setScrapedRows([]);
      setScrapedMeta(null);
    } catch { /* ignore */ }
  }

  // ── reddit management ─────────────────────────────────────────
  async function handleAddSubreddit(e: React.FormEvent) {
    e.preventDefault();
    const sub = newSubreddit.trim().replace(/^r\//i, "");
    if (!sub) return;
    setRedditMsg(null);
    try {
      const r = await fetch("/api/reddit/subreddits", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subreddit: sub }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed to add subreddit");
      setSubreddits(d.subreddits ?? []);
      setNewSubreddit("");
      setRedditMsg({ type: "ok", text: `r/${sub} added` });
    } catch (err) {
      setRedditMsg({ type: "err", text: String(err) });
    }
  }

  async function handleRemoveSubreddit(sub: string) {
    try {
      const r = await fetch(`/api/reddit/subreddits/${encodeURIComponent(sub)}`, { method: "DELETE" });
      const d = await r.json();
      setSubreddits(d.subreddits ?? []);
    } catch { /* ignore */ }
  }

  async function handleClearRedditResults() {
    if (!confirm("Clear all Reddit scraped results?")) return;
    try {
      await fetch("/api/reddit/results", { method: "DELETE" });
      setRedditRows([]);
      setRedditPosts([]);
      setRedditMeta(null);
    } catch { /* ignore */ }
  }

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString());
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, []);

  const postsWithText = redditPosts.filter((post) => post.text.trim().length > 0).length;
  const postsWithImages = redditPosts.filter((post) => post.image_files.length > 0 || post.image_urls.length > 0).length;
  const postsWithUrls = redditPosts.filter((post) => post.urls.length > 0).length;
  const keywordCounts = new Map<string, number>();
  for (const post of redditPosts) {
    for (const keyword of post.matched_keywords.split("|").map((part) => part.trim()).filter(Boolean)) {
      keywordCounts.set(keyword, (keywordCounts.get(keyword) ?? 0) + 1);
    }
  }

  // ── render ────────────────────────────────────────────────────
  const countFor = (keyword: string) => {
    const key = keyword.toLowerCase();
    let total = 0;
    for (const [name, count] of keywordCounts) {
      if (name.toLowerCase() === key) total += count;
    }
    return total;
  };
  const listed = new Set(keywords.map((keyword) => keyword.toLowerCase()));
  const keywordBars: [string, number][] = keywords.map((keyword) => [keyword, countFor(keyword)]);
  for (const [name, count] of keywordCounts) {
    if (!listed.has(name.toLowerCase())) keywordBars.push([name, count]);
  }
  const barMax = Math.max(1, ...keywordBars.map(([, count]) => count));
  const mix = [
    { label: "Text", value: postsWithText, color: "#3dff8a" },
    { label: "Images", value: postsWithImages, color: "#7dffb3" },
    { label: "Links", value: postsWithUrls, color: "#b6ffd4" },
  ];
  const mixTotal = Math.max(1, mix.reduce((sum, item) => sum + item.value, 0));
  let donutCursor = 0;
  const donut = mix.map((item) => {
    const start = donutCursor;
    const share = item.value / mixTotal;
    donutCursor += share;
    return { ...item, start, share };
  });
  const processing = redditScraperRunning || redditAutoScrape;

  return (
    <main className="dash">
      <div className="topbar">
        <div>
          <h1>ThreatRadar</h1>
          <p className="sub">Green radar for candidate posts. A keyword match is not a scam label.</p>
        </div>
        <nav className="tabs">
          <Link href="/" className={onDash ? "active" : ""}>Dashboard</Link>
          <Link href="/watch" className={onWatch ? "active" : ""}>Watch</Link>
          <Link href="/setup" className={onSetup ? "active" : ""}>Setup</Link>
        </nav>
      </div>

      {onDash && (
        <section className="board">
          <div className="radar-card">
            <div className="radar-head">
              <span>Scan</span>
              <strong className={processing ? "live" : ""}>{processing ? "PROCESSING" : "IDLE"}</strong>
            </div>
            <svg className="radar" viewBox="0 0 200 200" aria-hidden="true">
              <circle cx="100" cy="100" r="78" />
              <circle cx="100" cy="100" r="52" />
              <circle cx="100" cy="100" r="26" />
              <line x1="100" y1="22" x2="100" y2="178" />
              <line x1="22" y1="100" x2="178" y2="100" />
              <path className={processing ? "sweep" : "sweep idle"} d="M100 100 L100 22 A78 78 0 0 1 178 100 Z" />
              {keywordBars.slice(0, 8).map(([keyword], index) => {
                const angle = (index / Math.max(keywordBars.length, 1)) * Math.PI * 2;
                const radius = 36 + (index % 3) * 16;
                return <circle key={keyword} className="blip" cx={100 + Math.cos(angle) * radius} cy={100 + Math.sin(angle) * radius} r="3.5" />;
              })}
            </svg>
            <p className="muted">{clock} · scope {redditSearchScope} · {keywords.length} keywords</p>
          </div>

          <div className="process-card">
            <h2>Processing</h2>
            <ol className="steps">
              <li className={keywords.length ? "done" : ""}><span>1</span> Keywords loaded <b>{keywords.length}</b></li>
              <li className={subreddits.length || redditSearchScope === "global" ? "done" : ""}><span>2</span> Search scope <b>{redditSearchScope}</b></li>
              <li className={processing ? "done" : ""}><span>3</span> Collector <b>{processing ? "running" : "stopped"}</b></li>
              <li className={redditPosts.length ? "done" : ""}><span>4</span> Posts saved <b>{redditPosts.length}</b></li>
              <li className={postsWithImages ? "done" : ""}><span>5</span> Images kept <b>{postsWithImages}</b></li>
            </ol>
            <p className="muted">
              {redditMeta?.lastModified
                ? `Last Reddit write ${new Date(redditMeta.lastModified).toLocaleString()}`
                : "No Reddit file yet"}
            </p>
          </div>

          <div className="chart-card">
            <h2>What was collected</h2>
            <svg className="donut" viewBox="0 0 120 120" role="img" aria-label="Text, images, and links">
              <circle cx="60" cy="60" r="42" className="donut-track" />
              {donut.map((item) => (
                <circle key={item.label} cx="60" cy="60" r="42" className="donut-seg"
                  stroke={item.color}
                  strokeDasharray={`${item.share * 264} 264`}
                  strokeDashoffset={-item.start * 264} />
              ))}
              <text x="60" y="56" textAnchor="middle">{redditPosts.length}</text>
              <text x="60" y="72" textAnchor="middle" className="donut-label">posts</text>
            </svg>
            <ul className="legend">
              {mix.map((item) => <li key={item.label}><i style={{ background: item.color }} />{item.label} <b>{item.value}</b></li>)}
            </ul>
          </div>

          <div className="chart-card wide">
            <h2>Keyword chart</h2>
            <div className="bars">
              {keywordBars.length === 0 && <p className="muted">Add keywords on the Setup page.</p>}
              {keywordBars.map(([keyword, count]) => (
                <div key={keyword} className="bar-row">
                  <span title={keyword}>{keyword}</span>
                  <div className="bar-track"><div className="bar-fill" style={{ width: `${(count / barMax) * 100}%` }} /></div>
                  <b>{count}</b>
                </div>
              ))}
            </div>
          </div>

          <div className="stat-row">
            <article><span>Reddit domains</span><strong>{redditMeta?.count ?? redditRows.length}</strong></article>
            <article><span>Telegram domains</span><strong>{scrapedMeta?.count ?? scrapedRows.length}</strong></article>
            <article><span>Filtered domains</span><strong>{filteredMeta?.matchedCount ?? filteredDomains.length}</strong></article>
            <article><span>Saved files</span><strong>{files.length}</strong></article>
            <article><span>Subreddits</span><strong>{subreddits.length}</strong></article>
          </div>
        </section>
      )}

      {onWatch && <WatchPosts />}

      {onSetup && <div className="setup-panel">
      {/* ── TELEGRAM LOGIN ───────────────────────────────────── */}
      <div className="card">
        <h2>
          Telegram Login
          {authStatus?.step === "done"
            ? <span className="badge" style={{ background: "var(--ok, #27ae60)" }}>● Connected</span>
            : <span className="badge" style={{ background: "var(--err, #c0392b)" }}>● Not logged in</span>
          }
        </h2>

        {authStatus?.step === "done" ? (
          <div>
            <p className="muted" style={{ margin: "0 0 0.8rem" }}>
              Signed in as <strong>{authStatus.name}</strong>
              {authStatus.username && ` (@${authStatus.username})`}
              {authStatus.phone && ` · ${authStatus.phone}`}
            </p>
            <button
              onClick={handleLogout}
              disabled={authLoading}
              style={{ width: "auto", padding: "0.4rem 1.2rem",
                background: "var(--err, #c0392b)" }}
            >
              {authLoading ? "Logging out…" : "Log out"}
            </button>
          </div>
        ) : (
          <>
            {/* Step 1 — phone */}
            {(authStatus?.step === "none" || !authStatus || authStatus.step === "error") && (
              <form onSubmit={handleRequestCode}
                style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                <input
                  type="tel"
                  placeholder="+94771234567"
                  value={authPhone}
                  onChange={(e) => setAuthPhone(e.target.value)}
                  style={{ flex: 1, minWidth: "160px" }}
                />
                <button type="submit" disabled={authLoading}
                  style={{ width: "auto", padding: "0 1.2rem" }}>
                  {authLoading ? "Sending…" : "Send code"}
                </button>
              </form>
            )}

            {/* Step 2 — verification code */}
            {authStatus?.step === "code_sent" && (
              <form onSubmit={handleVerifyCode}
                style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                <input
                  type="text"
                  placeholder="Enter code from Telegram app"
                  value={authCode}
                  onChange={(e) => setAuthCode(e.target.value)}
                  style={{ flex: 1, minWidth: "160px" }}
                  autoFocus
                />
                <button type="submit" disabled={authLoading}
                  style={{ width: "auto", padding: "0 1.2rem" }}>
                  {authLoading ? "Verifying…" : "Verify code"}
                </button>
                <button type="button" onClick={() => setAuthStatus({ success: false, step: "none" })}
                  style={{ width: "auto", padding: "0 0.8rem", background: "var(--surface2, #333)" }}>
                  Back
                </button>
              </form>
            )}

            {/* Step 3 — 2FA password */}
            {authStatus?.step === "password_needed" && (
              <form onSubmit={handleVerifyPassword}
                style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                <input
                  type="password"
                  placeholder="Telegram 2FA password"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  style={{ flex: 1, minWidth: "160px" }}
                  autoFocus
                />
                <button type="submit" disabled={authLoading}
                  style={{ width: "auto", padding: "0 1.2rem" }}>
                  {authLoading ? "Checking…" : "Submit password"}
                </button>
              </form>
            )}
          </>
        )}

        {authMsg && (
          <div className={`msg ${authMsg.type === "ok" ? "ok" : "err"}`}
            style={{ marginTop: "0.6rem" }}>
            {authMsg.text}
          </div>
        )}
      </div>

      {/* ── REDDIT LOGIN ─────────────────────────────────────── */}
      <div className="card">
        <h2>
          Reddit Login
          {redditAuthStatus?.step === "done"
            ? <span className="badge" style={{ background: "var(--ok, #27ae60)" }}>● Connected</span>
            : <span className="badge" style={{ background: "var(--err, #c0392b)" }}>● Not logged in</span>
          }
        </h2>
        <p className="muted" style={{ marginTop: 0 }}>
          {redditCloudBackend
            ? "Log in with your Reddit account below — cookies are saved on the server for scraping. (No browser window on Vercel; that only works on localhost.)"
            : "Log in with Reddit username/password, open a browser window, or paste exported session JSON."}
        </p>

        {redditCloudBackend && !redditPlaywrightReady && redditAuthStatus?.step !== "done" && (
          <div className="msg err" style={{ marginBottom: "0.8rem" }}>
            Password login needs Chromium on Render (not installed yet).{" "}
            <strong>Use “Import session JSON”</strong> — paste your{" "}
            <code>reddit_session.json</code> from your PC.
          </div>
        )}

        {redditCloudBackend && redditAuthStatus?.step !== "done" && redditPlaywrightReady && (
          <div className="msg" style={{ marginBottom: "0.8rem", background: "var(--surface2, #2a2a2a)" }}>
            <strong>Vercel tip:</strong> use <strong>Reddit username + password</strong> below, or paste cookies after logging in on{" "}
            <a href="https://www.reddit.com/login" target="_blank" rel="noreferrer">reddit.com</a>{" "}
            (export with a cookie extension → paste JSON). For permanent deploys, set <code>REDDIT_SESSION_B64</code> on Render.
          </div>
        )}

        {redditAuthStatus?.step === "done" ? (
          <div>
            <p className="muted" style={{ margin: "0 0 0.8rem" }}>
              Session active{redditAuthStatus.username ? ` · ${redditAuthStatus.username}` : ""}
            </p>
            <button
              onClick={handleRedditLogout}
              disabled={redditAuthLoading}
              style={{ width: "auto", padding: "0.4rem 1.2rem", background: "var(--err, #c0392b)" }}
            >
              {redditAuthLoading ? "Logging out…" : "Log out"}
            </button>
          </div>
        ) : (
          <>
            {redditAuthStatus?.step === "browser_open" ? (
              <div>
                <p className="muted" style={{ margin: "0 0 0.8rem" }}>
                  {redditAuthStatus.message ?? "Complete login in the browser window…"}
                </p>
                <p className="muted" style={{ margin: 0, fontSize: "0.85rem" }}>
                  Waiting for Reddit login… this page updates automatically.
                </p>
              </div>
            ) : null}

            {redditCredentialLogin && (
              <form onSubmit={handleRedditLogin} style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: redditBrowserLogin ? "0.8rem" : 0 }}>
                <input
                  type="text"
                  placeholder="Reddit username or email"
                  value={redditUsername}
                  onChange={(e) => setRedditUsername(e.target.value)}
                  style={{ flex: 1, minWidth: "160px" }}
                  autoComplete="username"
                />
                <input
                  type="password"
                  placeholder="Password"
                  value={redditPassword}
                  onChange={(e) => setRedditPassword(e.target.value)}
                  style={{ flex: 1, minWidth: "160px" }}
                  autoComplete="current-password"
                />
                <button type="submit" disabled={redditAuthLoading}
                  style={{ width: "auto", padding: "0 1.2rem" }}>
                  {redditAuthLoading ? "Logging in…" : "Log in & save session"}
                </button>
              </form>
            )}

            <button
              type="button"
              onClick={() => setShowRedditImport((v) => !v)}
              style={{ marginTop: "0.8rem", width: "auto", padding: "0.3rem 0.8rem",
                background: "var(--surface2, #333)" }}
            >
              {showRedditImport ? "Hide cookie import" : "Or paste exported cookies / session JSON"}
            </button>

            {showRedditImport && (
              <form onSubmit={handleRedditImportSession} style={{ marginTop: "0.6rem" }}>
                <p className="muted" style={{ margin: "0 0 0.4rem", fontSize: "0.85rem" }}>
                  1. Log in at{" "}
                  <a href="https://www.reddit.com/login" target="_blank" rel="noreferrer">reddit.com/login</a>
                  {" "}→ 2. Export cookies (Playwright <code>reddit_session.json</code>, or Cookie-Editor extension JSON array)
                  {" "}→ 3. Paste below → Import
                </p>
                <textarea
                  placeholder='{ "cookies": [ ... ], "origins": [ ... ] }  OR  [ { "name": "reddit_session", ... } ]'
                  value={redditSessionJson}
                  onChange={(e) => setRedditSessionJson(e.target.value)}
                  rows={6}
                  style={{ width: "100%", fontFamily: "monospace", fontSize: "0.8rem" }}
                />
                <button type="submit" disabled={redditAuthLoading}
                  style={{ marginTop: "0.4rem", width: "auto", padding: "0.3rem 0.8rem" }}>
                  Import & save session
                </button>
              </form>
            )}

            {redditBrowserLogin && (
              <details style={{ marginTop: "0.8rem" }}>
                <summary className="muted" style={{ cursor: "pointer", fontSize: "0.85rem" }}>
                  Advanced: open browser window (localhost only)
                </summary>
                <button
                  type="button"
                  onClick={handleStartRedditBrowserLogin}
                  disabled={redditAuthLoading}
                  style={{ marginTop: "0.6rem", width: "auto", padding: "0.5rem 1.4rem" }}
                >
                  {redditAuthLoading ? "Opening browser…" : "Open Reddit login window"}
                </button>
              </details>
            )}
          </>
        )}

        {redditAuthMsg && (
          <div className={`msg ${redditAuthMsg.type === "ok" ? "ok" : "err"}`}
            style={{ marginTop: "0.6rem" }}>
            {redditAuthMsg.text}
          </div>
        )}
      </div>

      {account?.account && (
        <div className="card">
          <h2>
            Account
            <span className="badge">{account.account.license_name}</span>
          </h2>
          <p className="muted" style={{ margin: 0 }}>
            {account.account.email} · {account.account.status}
          </p>
        </div>
      )}

      {/* ── KEYWORD MANAGEMENT ──────────────────────────────── */}
      <div className="card">
        <h2>Scam Keywords</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Telegram and Reddit scrapers only process posts/messages containing these keywords,
          then extract suspicious external URLs from matching content.
        </p>
        <form onSubmit={handleAddKeyword} style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <input
            type="text"
            placeholder="e.g. airdrop, giveaway, profit…"
            value={newKeyword}
            onChange={(e) => setNewKeyword(e.target.value)}
            style={{ flex: 1, minWidth: "180px" }}
          />
          <button type="submit" style={{ width: "auto", padding: "0 1.2rem" }}>
            Add keyword
          </button>
        </form>
        {kwMsg && (
          <div className={`msg ${kwMsg.type === "ok" ? "ok" : "err"}`} style={{ marginTop: "0.6rem" }}>
            {kwMsg.text}
          </div>
        )}
        {keywords.length > 0 ? (
          <ul className="file-list" style={{ marginTop: "0.8rem" }}>
            {keywords.map((kw) => (
              <li key={kw}>
                <span>{kw}</span>
                <button
                  onClick={() => handleRemoveKeyword(kw)}
                  style={{ width: "auto", padding: "0.2rem 0.7rem", background: "var(--err, #c0392b)" }}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted" style={{ marginTop: "0.6rem" }}>
            No keywords yet — add some above. The scraper will collect all URLs if no keywords are set.
          </p>
        )}
      </div>

      {/* ── SCRAPED DOMAINS (TELEGRAM) ───────────────────────── */}
      <div className="card">
        <h2>
          Telegram — Today&apos;s New Suspicious Domains
          {scrapedMeta && (
            <span className="badge" style={{ marginLeft: "0.5rem" }}>
              {scrapedMeta.count} new today
            </span>
          )}
        </h2>
        {scrapedMeta?.lastModified && (
          <p className="muted" style={{ marginTop: 0, marginBottom: "0.6rem" }}>
            Today (UTC): {scrapedMeta.today ?? "—"}
            {scrapedMeta.seenDomainsTotal != null &&
              ` · ${scrapedMeta.seenDomainsTotal.toLocaleString()} domains known (skipped as duplicates)`}
            {" · "}Last updated: {new Date(scrapedMeta.lastModified).toLocaleString()} · refreshes every 30 s
          </p>
        )}
        <p className="muted">{scrapedRows.length} domains today. Open Dashboard for the count.</p>
        {scrapedRows.length > 0 && (
          <button
            onClick={handleClearResults}
            style={{ marginTop: "0.8rem", width: "auto", padding: "0.4rem 1rem",
              background: "var(--err, #c0392b)" }}
          >
            Clear results
          </button>
        )}
      </div>

      {/* ── REDDIT SCRAPER ──────────────────────────────────── */}
      <div className="card">
        <h2>
          Reddit Scraper
          <span className="badge" style={{
            marginLeft: "0.5rem",
            background: redditAutoScrape ? "var(--ok, #27ae60)" : "var(--surface2, #555)",
          }}>
            {redditAutoScrape ? (redditScraperRunning ? "● Running" : "● ON") : "○ OFF"}
          </span>
        </h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Each <strong>Scam Keyword</strong> can search <strong>all of Reddit</strong> or only
          your listed subreddits, then extract suspicious external URLs from matching posts.
        </p>

        <label style={{ display: "block", marginBottom: "0.8rem" }}>
          <span className="muted" style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.85rem" }}>
            Search scope
          </span>
          <select
            value={redditSearchScope}
            onChange={(e) => handleRedditSearchScopeChange(e.target.value as "global" | "subreddits" | "both")}
            style={{ width: "100%", maxWidth: "320px" }}
          >
            <option value="global">All of Reddit (per keyword)</option>
            <option value="subreddits">Subreddits only</option>
            <option value="both">Both (global + subreddits)</option>
          </select>
        </label>

        <label className="check" style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.8rem" }}>
          <input
            type="checkbox"
            checked={redditAutoScrape}
            onChange={handleToggleRedditScrape}
          />
          Auto-scrape Reddit (on/off)
        </label>

        <label style={{ display: "block", marginBottom: "0.8rem" }}>
          <span className="muted" style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.85rem" }}>
            Scrape interval (recommended: 5 min to avoid Reddit rate limits)
          </span>
          <select
            value={redditPollInterval}
            onChange={(e) => handleRedditPollIntervalChange(Number(e.target.value))}
            style={{ width: "100%", maxWidth: "320px" }}
          >
            <option value={60}>Every 1 minute</option>
            <option value={120}>Every 2 minutes</option>
            <option value={300}>Every 5 minutes (recommended)</option>
            <option value={600}>Every 10 minutes</option>
          </select>
        </label>

        <p className="muted" style={{ margin: "0 0 0.8rem", fontSize: "0.85rem" }}>
          Global search opens each matching post and extracts URLs from the <strong>post body</strong> and <strong>comments</strong>.
          Example keyword: <code>earn money</code>
        </p>

        {keywords.length > 0 ? (
          <p className="muted" style={{ margin: "0 0 0.8rem", fontSize: "0.85rem" }}>
            {redditSearchScope !== "subreddits" && (
              <>Global search terms: {keywords.map((k) => (
                <span key={k} className="badge" style={{ marginRight: "0.3rem" }}>{k}</span>
              ))}<br /></>
            )}
            {redditSearchScope !== "global" && redditSearchScope !== "subreddits" && (
              <span>Also scanning listed subreddits below.<br /></span>
            )}
            {redditSearchScope === "subreddits" && (
              <>Subreddit filters: {keywords.map((k) => (
                <span key={k} className="badge" style={{ marginRight: "0.3rem" }}>{k}</span>
              ))}</>
            )}
          </p>
        ) : (
          <p className="muted" style={{ margin: "0 0 0.8rem", fontSize: "0.85rem" }}>
            {redditSearchScope === "global"
              ? "Add keywords above — each keyword searches all of Reddit."
              : "No keywords set — all posts in subreddits will be scanned."}
          </p>
        )}

        {(redditSearchScope === "subreddits" || redditSearchScope === "both") && (
          <>
        <h3 style={{ margin: "0 0 0.4rem", fontSize: "1rem" }}>Subreddits to watch</h3>
        <form onSubmit={handleAddSubreddit} style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <input
            type="text"
            placeholder="e.g. cryptoscams, scams…"
            value={newSubreddit}
            onChange={(e) => setNewSubreddit(e.target.value)}
            style={{ flex: 1, minWidth: "180px" }}
          />
          <button type="submit" style={{ width: "auto", padding: "0 1.2rem" }}>
            Add subreddit
          </button>
        </form>
        {subreddits.length > 0 ? (
          <ul className="file-list" style={{ marginTop: "0.8rem" }}>
            {subreddits.map((sub) => (
              <li key={sub}>
                <span>r/{sub}</span>
                <button
                  onClick={() => handleRemoveSubreddit(sub)}
                  style={{ width: "auto", padding: "0.2rem 0.7rem", background: "var(--err, #c0392b)" }}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted" style={{ marginTop: "0.6rem" }}>
            No subreddits yet — add some above.
          </p>
        )}
          </>
        )}

        {redditMsg && (
          <div className={`msg ${redditMsg.type === "ok" ? "ok" : "err"}`} style={{ marginTop: "0.6rem" }}>
            {redditMsg.text}
          </div>
        )}
      </div>

      {/* ── SCRAPED DOMAINS (REDDIT) ────────────────────────── */}
      <div className="card">
        <h2>
          Reddit — Scraped Suspicious Domains
          {redditMeta && (
            <span className="badge" style={{ marginLeft: "0.5rem" }}>
              {redditMeta.count} domains
            </span>
          )}
        </h2>
        {redditMeta?.lastModified && (
          <p className="muted" style={{ marginTop: 0, marginBottom: "0.6rem" }}>
            Last updated: {new Date(redditMeta.lastModified).toLocaleString()} · refreshes every 30 s
          </p>
        )}
        <p className="muted">{redditPosts.length} posts, {redditRows.length} domains. Counts are on the Dashboard.</p>
        {(redditRows.length > 0 || redditPosts.length > 0) && (
          <button
            onClick={handleClearRedditResults}
            style={{ marginTop: "0.8rem", width: "auto", padding: "0.4rem 1rem",
              background: "var(--err, #c0392b)" }}
          >
            Clear Reddit results
          </button>
        )}
      </div>

      {/* ── DOMAIN FILTER (domains-monitor API) ──────────────── */}
      <div className="card">
        <h2>Filtered Domain List (API download)</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          After downloading from domains-monitor.com, filter by suspicious keywords and brand mimicry
          (e.g. g00gle.com, rnicrosoft.com). Results saved to JSON — separate from Telegram/Reddit scrapers.
        </p>

        <h3 style={{ fontSize: "1rem", marginBottom: "0.5rem" }}>Suspicious domain keywords</h3>
        <form onSubmit={handleAddDomainKeyword} style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <input
            type="text"
            placeholder="e.g. airdrop, login, verify, crypto-wallet…"
            value={newDomainKeyword}
            onChange={(e) => setNewDomainKeyword(e.target.value)}
            style={{ flex: 1, minWidth: "180px" }}
          />
          <button type="submit" style={{ width: "auto", padding: "0 1.2rem" }}>
            Add keyword
          </button>
        </form>
        {domainKwMsg && (
          <div className={`msg ${domainKwMsg.type === "ok" ? "ok" : "err"}`} style={{ marginTop: "0.6rem" }}>
            {domainKwMsg.text}
          </div>
        )}
        {domainKeywords.length > 0 ? (
          <ul className="file-list" style={{ marginTop: "0.8rem" }}>
            {domainKeywords.map((kw) => (
              <li key={kw}>
                <span>{kw}</span>
                <button
                  onClick={() => handleRemoveDomainKeyword(kw)}
                  style={{ width: "auto", padding: "0.2rem 0.7rem", background: "var(--err, #c0392b)" }}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted" style={{ marginTop: "0.6rem" }}>
            No domain keywords yet. Brand mimicry detection still runs (google, microsoft, paypal, binance…).
          </p>
        )}

        <div style={{ marginTop: "1rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button
            type="button"
            onClick={handleRunDomainFilter}
            disabled={filterLoading}
            style={{ width: "auto", padding: "0.4rem 1.2rem" }}
          >
            {filterLoading ? "Filtering…" : "Filter latest download"}
          </button>
        </div>

        <h3 style={{ fontSize: "1rem", marginTop: "1.2rem", marginBottom: "0.5rem" }}>
          Filtered suspicious domains
          {filteredMeta && (
            <span className="badge" style={{ marginLeft: "0.5rem" }}>
              {filteredMeta.matchedCount} matches
            </span>
          )}
        </h3>
        {filteredMeta?.sourceFile && (
          <p className="muted" style={{ marginTop: 0, marginBottom: "0.6rem" }}>
            Source: {filteredMeta.sourceFile}
            {filteredMeta.filteredAt &&
              ` · ${new Date(filteredMeta.filteredAt).toLocaleString()}`}
            {filteredMeta.totalScanned > 0 &&
              ` · scanned ${filteredMeta.totalScanned.toLocaleString()}`}
          </p>
        )}
        {filteredMeta && filteredMeta.matchedCount > 0 && (
          <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "0.8rem" }}>
            <a
              href={`/api/domain-filter/download?format=txt${
                filteredMeta.savedFile
                  ? `&file=${encodeURIComponent(filteredMeta.savedFile)}`
                  : ""
              }`}
              download
              style={{ width: "auto" }}
            >
              Download TXT ({filteredMeta.matchedCount.toLocaleString()} domains)
            </a>
            <a
              href={`/api/domain-filter/download?format=json${
                filteredMeta.savedFile
                  ? `&file=${encodeURIComponent(filteredMeta.savedFile)}`
                  : ""
              }`}
              download
              style={{ width: "auto" }}
            >
              Download JSON (full details)
            </a>
          </div>
        )}
        <p className="muted">
          {filteredDomains.length === 0
            ? "No filtered results yet. Download a domain list, then filter."
            : `${filteredMeta?.matchedCount ?? filteredDomains.length} domains matched. The count is on the Dashboard.`}
        </p>
      </div>

      {/* ── DOMAIN DOWNLOADER ────────────────────────────────── */}
      <div className="card">
        <h2>Download domain list</h2>
        <form onSubmit={handleDownload}>
          <div className="row">
            <div>
              <label htmlFor="zone">Zone / feed</label>
              <select id="zone" value={zone} onChange={(e) => setZone(e.target.value)}>
                <option value="dailyupdate">dailyupdate (new today)</option>
                <option value="dailyremove">dailyremove (removed today)</option>
                <option value="weeklyupdate">weeklyupdate</option>
                <option value="monthlyupdate">monthlyupdate</option>
                <option value="com">com</option>
                <option value="net">net</option>
                <option value="full">full (very large)</option>
              </select>
            </div>
            <div>
              <label htmlFor="format">Format</label>
              <select id="format" value={format}
                onChange={(e) => setFormat(e.target.value)} disabled={useFeed}>
                <option value="text">text</option>
                <option value="zip">zip</option>
                <option value="json">json</option>
              </select>
            </div>
          </div>
          <label className="check">
            <input type="checkbox" checked={useFeed}
              onChange={(e) => setUseFeed(e.target.checked)} />
            Use JSON feed API (TYPE/json)
          </label>
          <button type="submit" disabled={loading}>
            {loading ? "Downloading…" : "Download & save"}
          </button>
          {message && (
            <div className={`msg ${message.type === "ok" ? "ok" : "err"}`}>
              {message.text}
            </div>
          )}
        </form>
      </div>

      {/* ── SAVED FILES ──────────────────────────────────────── */}
      <div className="card">
        <h2>Saved files</h2>
        {files.length === 0 ? (
          <p className="muted">No downloads yet.</p>
        ) : (
          <ul className="file-list">
            {files.map((f) => (
              <li key={f.name}>
                <span>
                  {f.name}
                  <span className="muted" style={{ marginLeft: "0.5rem" }}>
                    {(f.bytes / 1024 / 1024).toFixed(2)} MB
                  </span>
                </span>
                <a href={`/api/downloads/${encodeURIComponent(f.name)}`} download>
                  Download
                </a>
              </li>
            ))}
          </ul>
        )}
      </div>

      <p className="muted">
        Token in <code>backend/.env</code> · Backend URL via <code>BACKEND_URL</code>
      </p>
      </div>}
    </main>
  );
}
