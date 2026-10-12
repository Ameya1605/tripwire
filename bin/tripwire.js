#!/usr/bin/env node

/**
 * Tripwire CLI - Node.js binary wrapper
 * Allows running Tripwire via `npx tripwire-sec` or `npm install -g tripwire-sec`
 */

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const args = process.argv.slice(2);

// Check if Python virtual environment or system Python is available
function resolvePythonCommand() {
  const rootDir = path.resolve(__dirname, "..");
  const venvPythonWin = path.join(rootDir, "venv", "Scripts", "python.exe");
  const venvPythonUnix = path.join(rootDir, "venv", "bin", "python");

  if (fs.existsSync(venvPythonWin)) return venvPythonWin;
  if (fs.existsSync(venvPythonUnix)) return venvPythonUnix;

  return process.platform === "win32" ? "python" : "python3";
}

const pythonCmd = resolvePythonCommand();
const cliModule = "tripwire.cli.main";

const child = spawn(pythonCmd, ["-m", cliModule, ...args], {
  stdio: "inherit",
  shell: process.platform === "win32",
});

child.on("exit", (code) => {
  process.exit(code || 0);
});
