const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const dist = path.join(root, "dist");

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
}

build().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
