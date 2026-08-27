#!/usr/bin/env node

/**
 * encrypted-sqlite — NPX executable CLI wrapper.
 * Enables instant execution via: `npx encrypted-sqlite <command>`
 */

const { spawn, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const pythonScript = path.resolve(__dirname, '..', 'src', 'cli.py');
const args = process.argv.slice(2);

function findPythonBinary() {
  if (process.env.PYTHON_CMD) {
    return { cmd: process.env.PYTHON_CMD, prefixArgs: [] };
  }

  if (os.platform() === 'win32') {
    // 1. Try Windows 'py -3' launcher
    try {
      execSync('py -3 --version', { stdio: 'ignore' });
      return { cmd: 'py', prefixArgs: ['-3'] };
    } catch (_) {}

    // 2. Check standard Windows AppData python installations
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    const pyProgramsDir = path.join(localAppData, 'Programs', 'Python');
    if (fs.existsSync(pyProgramsDir)) {
      try {
        const subdirs = fs.readdirSync(pyProgramsDir).sort().reverse();
        for (const sub of subdirs) {
          const exe = path.join(pyProgramsDir, sub, 'python.exe');
          if (fs.existsSync(exe)) {
            return { cmd: exe, prefixArgs: [] };
          }
        }
      } catch (_) {}
    }

    // 3. Try standard 'python'
    try {
      execSync('python --version', { stdio: 'ignore' });
      return { cmd: 'python', prefixArgs: [] };
    } catch (_) {}
  } else {
    // Linux / macOS: check python3 first, then python
    try {
      execSync('python3 --version', { stdio: 'ignore' });
      return { cmd: 'python3', prefixArgs: [] };
    } catch (_) {
      try {
        execSync('python --version', { stdio: 'ignore' });
        return { cmd: 'python', prefixArgs: [] };
      } catch (_) {}
    }
  }

  return { cmd: 'python3', prefixArgs: [] };
}

const { cmd, prefixArgs } = findPythonBinary();
const finalArgs = [...prefixArgs, pythonScript, ...args];

const child = spawn(cmd, finalArgs, {
  stdio: 'inherit',
  env: process.env
});

child.on('error', (err) => {
  console.error('\n❌ Error: Python is required to run encrypted-sqlite.');
  console.error('Please install Python 3.10+ from https://www.python.org/ or add Python to your PATH.\n');
  process.exit(1);
});

child.on('close', (code) => {
  process.exit(code || 0);
});
