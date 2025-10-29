import { readFileSync } from "fs";
import { join } from "path";

let cachedVersion: string | null = null;

/**
 * Gets the application version from package.json
 * @returns The version string from package.json
 */
export function getAppVersion(): string {
  if (cachedVersion !== null) {
    return cachedVersion;
  }

  try {
    // Read package.json from the workspace root
    const packageJsonPath = join(process.cwd(), "package.json");
    const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf-8"));
    const version = packageJson.version || "0.0.1";
    cachedVersion = version;
    return version;
  } catch (error) {
    console.warn(
      "Failed to read version from package.json, using fallback:",
      error
    );
    const fallbackVersion = "0.0.1";
    cachedVersion = fallbackVersion;
    return fallbackVersion;
  }
}
