/**
 * Shell command execution utilities for the IOTA MCP server.
 */

import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

const MAX_BUFFER = 10 * 1024 * 1024; // 10 MB

/**
 * Run a shell command and return combined stdout/stderr output.
 * Captures errors gracefully so the MCP tool always returns text.
 */
export async function runCommand(
  cmd: string,
  cwd?: string,
): Promise<string> {
  try {
    const { stdout, stderr } = await execAsync(cmd, {
      cwd,
      maxBuffer: MAX_BUFFER,
      env: { ...process.env, PATH: process.env.PATH },
    });
    return stdout + (stderr ? `\n[stderr]: ${stderr}` : "");
  } catch (error: unknown) {
    const err = error as {
      message?: string;
      stdout?: string;
      stderr?: string;
    };
    return `Error: ${err.message ?? "unknown"}\n${err.stdout ?? ""}\n${err.stderr ?? ""}`;
  }
}
