const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const dist = path.join(root, "dist");
const treeSitterAssets = [
  ["web-tree-sitter", "tree-sitter.wasm"],
  ["tree-sitter-wasms", "out", "tree-sitter-javascript.wasm"],
  ["tree-sitter-wasms", "out", "tree-sitter-typescript.wasm"],
  ["tree-sitter-wasms", "out", "tree-sitter-tsx.wasm"],
  ["tree-sitter-wasms", "out", "tree-sitter-python.wasm"]
];

fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });

const common = {
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node18",
  sourcemap: false,
  logLevel: "info",
  external: ["vscode", "node:sqlite"],
  define: {
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV ?? "production")
  }
};

async function build() {
  await Promise.all([
    esbuild.build({
      ...common,
      entryPoints: [path.join(root, "src", "extension.ts")],
      outfile: path.join(dist, "extension.js")
    }),
    esbuild.build({
      ...common,
      entryPoints: [path.join(root, "src", "cli.ts")],
      outfile: path.join(dist, "cli.js")
    }),
    esbuild.build({
      ...common,
      entryPoints: [path.join(root, "src", "lspServer.ts")],
      outfile: path.join(dist, "lspServer.js")
    })
  ]);
  const assetDirectory = path.join(dist, "tree-sitter");
  fs.mkdirSync(assetDirectory, { recursive: true });
  for (const assetSegments of treeSitterAssets) {
    const source = path.join(root, "node_modules", ...assetSegments);
    fs.copyFileSync(source, path.join(assetDirectory, assetSegments.at(-1)));
  }
}

build().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
