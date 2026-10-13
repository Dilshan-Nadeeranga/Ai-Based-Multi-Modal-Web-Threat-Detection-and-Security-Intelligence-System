import pg from "pg";

const connectionString = (process.env.DATABASE_URL || "").trim();

export const pool = connectionString
  ? new pg.Pool({
      connectionString,
      max: 3,
      connectionTimeoutMillis: 15000,
    })
  : null;

function asList(value) {
  if (Array.isArray(value)) return value.map((item) => String(item)).filter(Boolean);
  if (!value) return [];
  return String(value).split(/\s+/).filter(Boolean);
}

export async function queryStoredPosts(limit) {
  if (!pool) return { configured: false, posts: [] };
  const { rows } = await pool.query(
    `SELECT post_id, subreddit, collected_at, matched_keywords, title, post_text,
            post_url, urls, image_urls, image_files, label_status
     FROM reddit_posts
     ORDER BY collected_at DESC NULLS LAST
     LIMIT $1`,
    [limit]
  );
  return {
    configured: true,
    posts: rows.map((row) => ({
      post_id: row.post_id,
      subreddit: row.subreddit || "",
      collected_at: row.collected_at ? new Date(row.collected_at).toISOString() : "",
      matched_keywords: asList(row.matched_keywords),
      caption: row.title || "",
      text: row.post_text || "",
      post_url: row.post_url || "",
      urls: asList(row.urls),
      image_urls: asList(row.image_urls),
      image_files: asList(row.image_files).map((file) => file.split(/[/\\]/).pop()),
      label_status: row.label_status || "not_annotated",
    })),
  };
}
