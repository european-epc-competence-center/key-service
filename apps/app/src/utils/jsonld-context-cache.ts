import * as fs from "fs";
import * as path from "path";
import logger from "./log/logger";

const MANIFEST_FILENAME = "manifest.json";

/** Conventional mount point for deploy-time context injection. */
export const DEFAULT_INJECT_CONTEXT_DIR = "/contexts";

export type ContextManifest = Record<string, string>;

/**
 * Resolves filesystem directories that hold persistent JSON-LD contexts.
 *
 * - If `JSONLD_CONTEXT_DIRS` is set, use those paths (platform path delimiter).
 * - Otherwise: `<cwd>/contexts`, plus `/contexts` when that directory exists.
 */
export function resolveContextCacheDirs(
  cwd: string = process.cwd(),
  envDirs: string | undefined = process.env.JSONLD_CONTEXT_DIRS,
  injectDir: string = DEFAULT_INJECT_CONTEXT_DIR,
  existsSync: (p: string) => boolean = fs.existsSync
): string[] {
  if (envDirs?.trim()) {
    return envDirs
      .split(path.delimiter)
      .map((d) => d.trim())
      .filter(Boolean);
  }

  const dirs = [path.resolve(cwd, "contexts")];
  if (existsSync(injectDir)) {
    dirs.push(injectDir);
  }
  return dirs;
}

/**
 * Persistent JSON-LD context documents loaded from the filesystem.
 * Bundled with the container and optionally extended via mounted directories.
 */
export class JsonLdContextCache {
  private static documents = new Map<string, unknown>();
  private static loaded = false;

  /** Test helper: clear loaded state. */
  static reset(): void {
    this.documents.clear();
    this.loaded = false;
  }

  /**
   * Load contexts from the given directories (or defaults).
   * Later directories override earlier ones for the same URL.
   */
  static load(dirs?: string[]): Map<string, unknown> {
    const targetDirs = dirs ?? resolveContextCacheDirs();
    if (!dirs && this.loaded) {
      return this.documents;
    }

    if (dirs) {
      this.documents.clear();
      this.loaded = false;
    }

    for (const dir of targetDirs) {
      this.loadDirectory(dir);
      this.loadChildManifestDirs(dir);
    }

    this.loaded = true;
    logger.info(
      `JSON-LD context cache loaded: ${this.documents.size} document(s) from ${targetDirs.length} director(y/ies)`,
      { dirs: targetDirs, urls: [...this.documents.keys()] }
    );
    return this.documents;
  }

  static get(url: string): unknown | undefined {
    if (!this.loaded) {
      this.load();
    }
    return this.documents.get(url);
  }

  static has(url: string): boolean {
    if (!this.loaded) {
      this.load();
    }
    return this.documents.has(url);
  }

  static size(): number {
    if (!this.loaded) {
      this.load();
    }
    return this.documents.size;
  }

  /** Load immediate child directories that contain their own manifest.json (e.g. contexts/gs1). */
  private static loadChildManifestDirs(dir: string): void {
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
      return;
    }

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (error) {
      logger.error(
        `JSON-LD context cache: failed to read directory ${dir}`,
        error
      );
      return;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const childDir = path.join(dir, entry.name);
      if (fs.existsSync(path.join(childDir, MANIFEST_FILENAME))) {
        this.loadDirectory(childDir);
      }
    }
  }

  private static loadDirectory(dir: string): void {
    const manifestPath = path.join(dir, MANIFEST_FILENAME);

    if (!fs.existsSync(manifestPath)) {
      if (!fs.existsSync(dir)) {
        logger.debug(
          `JSON-LD context cache: directory not found, skipping: ${dir}`
        );
        return;
      }
      logger.warn(
        `JSON-LD context cache: no ${MANIFEST_FILENAME} in ${dir}, skipping`
      );
      return;
    }

    let manifest: ContextManifest;
    try {
      manifest = JSON.parse(
        fs.readFileSync(manifestPath, "utf8")
      ) as ContextManifest;
    } catch (error) {
      logger.error(
        `JSON-LD context cache: failed to parse ${manifestPath}`,
        error
      );
      return;
    }

    for (const [url, relativePath] of Object.entries(manifest)) {
      if (!url || typeof relativePath !== "string") {
        logger.warn(
          `JSON-LD context cache: invalid manifest entry in ${manifestPath}`,
          { url, relativePath }
        );
        continue;
      }

      const resolvedDir = path.resolve(dir);
      const filePath = path.resolve(dir, relativePath);
      const relativeToDir = path.relative(resolvedDir, filePath);
      if (
        relativeToDir.startsWith("..") ||
        path.isAbsolute(relativeToDir)
      ) {
        logger.warn(
          `JSON-LD context cache: refusing path outside cache dir`,
          { url, relativePath, filePath, dir }
        );
        continue;
      }

      if (!fs.existsSync(filePath)) {
        logger.warn(
          `JSON-LD context cache: missing file for ${url}`,
          { filePath }
        );
        continue;
      }

      try {
        const document = JSON.parse(fs.readFileSync(filePath, "utf8"));
        this.documents.set(url, document);
      } catch (error) {
        logger.error(
          `JSON-LD context cache: failed to parse ${filePath}`,
          error
        );
      }
    }
  }
}
