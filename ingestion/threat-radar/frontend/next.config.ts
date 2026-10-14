import type { NextConfig } from "next";

// Server-only: never exposed to the browser.
// Locally set in frontend/.env.local as BACKEND_URL=http://localhost:4000
// On Netlify set via Site → Environment variables → BACKEND_URL=https://threatradar.onrender.com
const backend = process.env.BACKEND_URL ?? "http://localhost:4000";

const nextConfig: NextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
};

export default nextConfig;
