import path from "path";
import { fileURLToPath } from "url";

/** Resolve backend/ root from any file inside backend/scripts/ */
export function backendRootFrom(importMetaUrl) {
  return path.resolve(path.dirname(fileURLToPath(importMetaUrl)), "..");
}

/** Resolve backend/ root from any file directly under backend/ */
export function backendRootFromBackendFile(importMetaUrl) {
  return path.dirname(fileURLToPath(importMetaUrl));
}
