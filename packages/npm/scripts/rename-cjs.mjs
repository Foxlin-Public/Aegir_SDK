import { readdir, rename } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDirectory, "..");
const cjsRoot = resolve(packageRoot, "dist", "cjs");

await renameCompiledFiles(cjsRoot);

async function renameCompiledFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      await renameCompiledFiles(fullPath);
      continue;
    }

    if (extname(entry.name) !== ".js") {
      continue;
    }

    const targetPath = fullPath.replace(/\.js$/i, ".cjs");
    await rename(fullPath, targetPath);
  }
}
