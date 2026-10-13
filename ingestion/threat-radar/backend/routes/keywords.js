import { Router } from "express";
import { readKeywords, writeKeywords } from "../keywordsStore.js";

export const keywordsRouter = Router();

keywordsRouter.get("/", async (_req, res) => {
  res.json({ keywords: await readKeywords() });
});

keywordsRouter.post("/", async (req, res) => {
  const keyword = String(req.body?.keyword ?? "").trim().toLowerCase();
  if (!keyword) return res.status(400).json({ error: "keyword is required" });

  const keywords = await readKeywords();
  if (keywords.includes(keyword)) {
    return res.status(409).json({ error: "Keyword already exists" });
  }
  keywords.push(keyword);
  await writeKeywords(keywords);
  res.json({ keywords });
});

keywordsRouter.delete("/:keyword", async (req, res) => {
  const keyword = decodeURIComponent(req.params.keyword).trim().toLowerCase();
  const keywords = (await readKeywords()).filter((k) => k !== keyword);
  await writeKeywords(keywords);
  res.json({ keywords });
});

keywordsRouter.put("/", async (req, res) => {
  const incoming = req.body?.keywords;
  if (!Array.isArray(incoming)) {
    return res.status(400).json({ error: "keywords must be an array" });
  }
  const keywords = incoming
    .map((k) => String(k).trim().toLowerCase())
    .filter(Boolean);
  await writeKeywords(keywords);
  res.json({ keywords });
});
