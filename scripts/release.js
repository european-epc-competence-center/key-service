#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

// ANSI color codes for colored output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
};

function log(message, color = "reset") {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function getCurrentVersion() {
  const packagePath = path.join(__dirname, "..", "package.json");
  const package = JSON.parse(fs.readFileSync(packagePath, "utf8"));
  return package.version;
}

function updatePackageVersion(newVersion) {
  const packagePath = path.join(__dirname, "..", "package.json");
  const package = JSON.parse(fs.readFileSync(packagePath, "utf8"));
  package.version = newVersion;
  fs.writeFileSync(packagePath, JSON.stringify(package, null, 2) + "\n");
  log(`✓ Updated package.json version to ${newVersion}`, "green");
}

function updateChangelog(version, changes) {
  const changelogPath = path.join(__dirname, "..", "CHANGELOG.md");
  const today = new Date().toISOString().split("T")[0];

  let changelog = "";
  if (fs.existsSync(changelogPath)) {
    changelog = fs.readFileSync(changelogPath, "utf8");
  } else {
    changelog = `# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`;
  }

  const newEntry = `## [${version}] - ${today}

${changes}

`;

  // Insert new entry after the header, replacing any existing [Unreleased] section
  const lines = changelog.split("\n");
  let insertIndex = lines.findIndex((line) => line.startsWith("## ["));

  // If we found an [Unreleased] section, remove it
  if (insertIndex !== -1 && lines[insertIndex].includes("[Unreleased]")) {
    let endOfUnreleasedIndex = insertIndex + 1;
    while (
      endOfUnreleasedIndex < lines.length &&
      !lines[endOfUnreleasedIndex].startsWith("## [")
    ) {
      endOfUnreleasedIndex++;
    }
    lines.splice(insertIndex, endOfUnreleasedIndex - insertIndex, newEntry);
  } else {
    // No unreleased section found, insert at the normal position
    if (insertIndex === -1) insertIndex = lines.length;
    lines.splice(insertIndex, 0, newEntry);
  }

  fs.writeFileSync(changelogPath, lines.join("\n"));
  log(`✓ Updated CHANGELOG.md with version ${version}`, "green");
}

function bumpVersion(currentVersion, type) {
  const parts = currentVersion.split(".").map(Number);

  switch (type) {
    case "patch":
      parts[2]++;
      break;
    case "minor":
      parts[1]++;
      parts[2] = 0;
      break;
    case "major":
      parts[0]++;
      parts[1] = 0;
      parts[2] = 0;
      break;
    default:
      throw new Error(
        `Invalid version type: ${type}. Use 'patch', 'minor', or 'major'`
      );
  }

  return parts.join(".");
}

function commitAndTag(version) {
  try {
    // Check if we're in a git repository
    execSync("git status", { stdio: "ignore" });

    // Add files
    execSync("git add package.json CHANGELOG.md");

    // Commit
    execSync(`git commit -m "chore: release version ${version}"`, {
      stdio: "inherit",
    });

    // Tag
    execSync(`git tag -a v${version} -m "Release version ${version}"`, {
      stdio: "inherit",
    });

    log(`✓ Created git commit and tag v${version}`, "green");

    // Push changes and tags
    log("📤 Pushing changes to remote...", "yellow");
    execSync("git push && git push --tags", {
      stdio: "inherit",
    });

    log("✓ Successfully pushed changes and tags to remote", "green");
  } catch (error) {
    log("⚠ Git operations failed. Please commit and tag manually:", "yellow");
    log(`  git add package.json CHANGELOG.md`, "cyan");
    log(`  git commit -m "chore: release version ${version}"`, "cyan");
    log(`  git tag -a v${version} -m "Release version ${version}"`, "cyan");
    log(`  git push && git push --tags`, "cyan");
  }
}

function extractUnreleasedChanges() {
  const changelogPath = path.join(__dirname, "..", "CHANGELOG.md");

  if (!fs.existsSync(changelogPath)) {
    return null;
  }

  const changelog = fs.readFileSync(changelogPath, "utf8");
  const lines = changelog.split("\n");

  // Find the [Unreleased] section
  const unreleasedIndex = lines.findIndex(
    (line) => line.startsWith("## [") && line.includes("[Unreleased]")
  );

  if (unreleasedIndex === -1) {
    return null;
  }

  // Find the end of the unreleased section (next version section or end of file)
  let endIndex = unreleasedIndex + 1;
  while (endIndex < lines.length && !lines[endIndex].startsWith("## [")) {
    endIndex++;
  }

  // Extract the content between [Unreleased] and the next section
  const unreleasedLines = lines.slice(unreleasedIndex + 1, endIndex);

  // Remove empty lines at the beginning and end
  while (unreleasedLines.length > 0 && unreleasedLines[0].trim() === "") {
    unreleasedLines.shift();
  }
  while (
    unreleasedLines.length > 0 &&
    unreleasedLines[unreleasedLines.length - 1].trim() === ""
  ) {
    unreleasedLines.pop();
  }

  const changes = unreleasedLines.join("\n");
  return changes.trim() || null;
}

function main() {
  log("🚀 Key Service Release Tool", "bright");
  log("============================\n", "bright");

  // Parse command line arguments
  const args = process.argv.slice(2);
  const versionType = args[0];
  const skipGit = args.includes("--skip-git");

  if (!versionType || !["patch", "minor", "major"].includes(versionType)) {
    log("Usage: npm run release <patch|minor|major> [--skip-git]", "red");
    log("\nExamples:", "cyan");
    log("  npm run release patch    # 1.0.0 -> 1.0.1", "cyan");
    log("  npm run release minor    # 1.0.0 -> 1.1.0", "cyan");
    log("  npm run release major    # 1.0.0 -> 2.0.0", "cyan");
    process.exit(1);
  }

  const currentVersion = getCurrentVersion();
  const newVersion = bumpVersion(currentVersion, versionType);

  log(`Current version: ${currentVersion}`, "blue");
  log(`New version: ${newVersion}`, "green");
  log("");

  // Check for unreleased changelog entries
  const changes = extractUnreleasedChanges();

  if (!changes) {
    log("⚠ No unreleased changelog entries found in CHANGELOG.md", "yellow");
    log(
      "Please add entries under an '## [Unreleased]' section first.",
      "yellow"
    );
    log("\nExample format:", "cyan");
    log("## [Unreleased]", "cyan");
    log("", "cyan");
    log("### Added", "cyan");
    log("- New feature description", "cyan");
    log("", "cyan");
    log("### Changed", "cyan");
    log("- Changed feature description", "cyan");
    log("", "cyan");
    log("### Fixed", "cyan");
    log("- Bug fix description", "cyan");
    process.exit(1);
  }

  log("📝 Found unreleased changes:", "green");
  log(changes, "cyan");
  log("");

  // Update files
  updatePackageVersion(newVersion);
  updateChangelog(newVersion, changes);

  log("\n📋 Release Summary:", "bright");
  log(`Version: ${currentVersion} -> ${newVersion}`, "blue");
  log("Files updated:", "blue");
  log("  ✓ package.json", "green");
  log("  ✓ CHANGELOG.md", "green");

  if (!skipGit) {
    log("\n📝 Creating git commit and tag...", "yellow");
    commitAndTag(newVersion);
  }

  log("\n🎉 Release preparation complete!", "bright");
  log("\nNext steps:", "yellow");
  if (!skipGit) {
    log("1. The changes and tags have been pushed to remote", "green");
  }
  log("2. Set SERVICE_VERSION environment variable in deployment", "cyan");
  log(`   export SERVICE_VERSION=${newVersion}`, "cyan");
  log(
    "3. The GitLab pipeline will automatically build and tag the Docker image",
    "cyan"
  );
}

// Handle Ctrl+C gracefully
process.on("SIGINT", () => {
  log("\n\n❌ Release cancelled by user", "red");
  process.exit(130);
});

try {
  main();
} catch (error) {
  log(`\n❌ Error: ${error.message}`, "red");
  process.exit(1);
}
