const { spawnSync } = require("child_process");
const { version } = require("../package.json");

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const result = spawnSync(npm, ["exec", "--", "vsce", "package", "--out", `vibeguard-${version}.vsix`], {
  stdio: "inherit",
  shell: process.platform === "win32"
});

if (result.error) {
  throw result.error;
}
process.exitCode = result.status ?? 1;
