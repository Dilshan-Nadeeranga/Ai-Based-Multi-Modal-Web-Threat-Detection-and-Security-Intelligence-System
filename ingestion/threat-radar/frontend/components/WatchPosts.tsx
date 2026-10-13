"use client";

import { useEffect, useState } from "react";

const TEXT_PREVIEW = 140;

function previewText(text: string) {
  const clean = text.replace(/\s+/g, " ").trim();
  if (clean.length <= TEXT_PREVIEW) return { short: clean, clipped: false };
  const cut = clean.slice(0, TEXT_PREVIEW);
  const lastSpace = cut.lastIndexOf(" ");
  const bit = (lastSpace > 80 ? cut.slice(0, lastSpace) : cut).trim();
  return { short: `${bit}...`, clipped: true };
}

type StoredPost = {
  post_id: string;
  subreddit: string;
  collected_at: string;
  matched_keywords: string[];
  caption: string;
  text: string;
  post_url: string;
  urls: string[];
  image_files: string[];
  label_status: string;
};

export default function WatchPosts() {
  const [posts, setPosts] = useState<StoredPost[]>([]);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const response = await fetch("/api/reddit/stored?limit=100");
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Could not read stored posts");
        if (!cancelled) {
          setPosts(Array.isArray(data.results) ? data.results : []);
          setError("");
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Could not read stored posts");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    const timer = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  if (loading) return <p className="muted">Reading stored posts…</p>;
  if (error) return <p className="msg err">{error}</p>;
  if (posts.length === 0) return <p className="muted">No posts with an external link are stored yet.</p>;

  return (
    <section className="watch-list">
      <p className="muted">{posts.length} stored {posts.length === 1 ? "post" : "posts"}. A keyword match is not a scam label.</p>
      {posts.map((post) => {
        const image = post.image_files[0];
        const when = post.collected_at ? new Date(post.collected_at).toLocaleString() : "";
        const preview = previewText(post.text || "");
        const expanded = Boolean(open[post.post_id]);
        return (
          <article className="watch-card" key={post.post_id}>
            <header>
              <span>{post.subreddit || "reddit"}</span>
              <time>{when}</time>
            </header>
            <h2>Caption</h2>
            <p className="caption">{post.caption || "No caption"}</p>
            <h2>Text</h2>
            <p className="body-text">
              {post.text ? (expanded ? post.text : preview.short) : "No text"}
              {preview.clipped && (
                <button
                  type="button"
                  className="more"
                  onClick={() => setOpen((current) => ({ ...current, [post.post_id]: !current[post.post_id] }))}
                >
                  {expanded ? "See less" : "See more"}
                </button>
              )}
            </p>
            {post.urls.length > 0 && (
              <>
                <h2>External link</h2>
                <ul>
                  {post.urls.map((url) => (
                    <li key={url}>{url}</li>
                  ))}
                </ul>
              </>
            )}
            {image && (
              <img
                src={`/api/reddit/images/${encodeURIComponent(image)}`}
                alt=""
                onError={(event) => {
                  event.currentTarget.style.display = "none";
                }}
              />
            )}
            <footer>
              {post.matched_keywords.map((keyword) => (
                <em key={keyword}>{keyword}</em>
              ))}
              <span>{post.label_status === "not_annotated" ? "Not annotated" : post.label_status}</span>
            </footer>
          </article>
        );
      })}
    </section>
  );
}
