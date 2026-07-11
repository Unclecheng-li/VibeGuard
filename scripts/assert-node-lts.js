const major = Number.parseInt(process.versions.node.split(".")[0] ?? "", 10);

if (major === 20 || major === 22) {
  process.exit(0);
}

console.error(
  `VibeGuard tests require Node.js 20 or 22 LTS; detected ${process.versions.node}. Run "nvm use" before npm test.`
);
process.exit(1);
