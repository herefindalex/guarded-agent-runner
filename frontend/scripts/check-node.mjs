function supportsNodeVersion(version) {
  const [major, minor] = version.split('.').map(Number);
  return (
    (major === 20 && minor >= 19) ||
    (major === 22 && minor >= 12) ||
    major > 22
  );
}

if (process.argv.includes('--self-test')) {
  const cases = [
    ['18.19.1', false],
    ['20.18.9', false],
    ['20.19.0', true],
    ['21.7.3', false],
    ['22.11.0', false],
    ['22.12.0', true],
    ['24.0.0', true],
  ];
  for (const [version, expected] of cases) {
    if (supportsNodeVersion(version) !== expected) {
      throw new Error(`Node version contract regression for ${version}`);
    }
  }
  process.stdout.write('Node version contract: 7 cases passed.\n');
  process.exit(0);
}

if (!supportsNodeVersion(process.versions.node)) {
  process.stderr.write(
    `Unsupported Node.js ${process.versions.node}. ` +
      'The locked Vite/Rolldown toolchain requires Node ^20.19.0 or >=22.12.0. ' +
      'Use Node 24 for local frontend work, or run `make frontend-verify` for the pinned Docker build.\n',
  );
  process.exit(1);
}
