/**
 * SessionManager — singleton managing all Frida sessions, scripts, and messages.
 * Replaces the Python server's 4 separate global dicts with a unified state.
 */

import type frida from "frida";

export interface ScriptMessage {
  type: string;
  payload?: unknown;
  description?: string;
  stack?: string;
  data?: Buffer | null;
  timestamp: number;
}

export interface ManagedScript {
  id: string;
  fridaScript: frida.Script;
  source: string;
  persistent: boolean;
  rpcExports: string[];
  loadedAt: number;
}

export interface ManagedSession {
  id: string;
  fridaSession: frida.Session;
  device: frida.Device;
  pid: number;
  scripts: Map<string, ManagedScript>;
  messages: ScriptMessage[];
  createdAt: number;
}

let nextSessionNum = 1;
let nextScriptNum = 1;

export class SessionManager {
  private sessions = new Map<string, ManagedSession>();

  generateSessionId(pid: number): string {
    return `session_${pid}_${nextSessionNum++}`;
  }

  generateScriptId(): string {
    return `script_${nextScriptNum++}`;
  }

  addSession(
    id: string,
    fridaSession: frida.Session,
    device: frida.Device,
    pid: number,
  ): ManagedSession {
    const managed: ManagedSession = {
      id,
      fridaSession,
      device,
      pid,
      scripts: new Map(),
      messages: [],
      createdAt: Date.now(),
    };
    this.sessions.set(id, managed);

    // Auto-cleanup on detach
    fridaSession.detached.connect(() => {
      this.sessions.delete(id);
    });

    return managed;
  }

  getSession(id: string): ManagedSession | undefined {
    return this.sessions.get(id);
  }

  requireSession(id: string): ManagedSession {
    const s = this.sessions.get(id);
    if (!s) throw new Error(`Session '${id}' not found or detached`);
    return s;
  }

  listSessions(): ManagedSession[] {
    return [...this.sessions.values()];
  }

  removeSession(id: string): boolean {
    return this.sessions.delete(id);
  }

  addScript(
    sessionId: string,
    scriptId: string,
    fridaScript: frida.Script,
    source: string,
    persistent: boolean,
    rpcExports: string[] = [],
  ): ManagedScript {
    const session = this.requireSession(sessionId);
    const managed: ManagedScript = {
      id: scriptId,
      fridaScript,
      source,
      persistent,
      rpcExports,
      loadedAt: Date.now(),
    };
    session.scripts.set(scriptId, managed);
    return managed;
  }

  getScript(sessionId: string, scriptId: string): ManagedScript | undefined {
    return this.sessions.get(sessionId)?.scripts.get(scriptId);
  }

  requireScript(sessionId: string, scriptId: string): ManagedScript {
    const s = this.getScript(sessionId, scriptId);
    if (!s) throw new Error(`Script '${scriptId}' not found in session '${sessionId}'`);
    return s;
  }

  removeScript(sessionId: string, scriptId: string): boolean {
    return this.sessions.get(sessionId)?.scripts.delete(scriptId) ?? false;
  }

  pushMessage(sessionId: string, msg: ScriptMessage): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.messages.push(msg);
      // Cap at 1000 messages to prevent unbounded growth
      if (session.messages.length > 1000) {
        session.messages.splice(0, session.messages.length - 1000);
      }
    }
  }

  peekMessages(sessionId: string): ScriptMessage[] {
    const session = this.sessions.get(sessionId);
    if (!session) return [];
    return [...session.messages];
  }

  clearMessages(sessionId: string): number {
    const session = this.sessions.get(sessionId);
    if (!session) return 0;
    const cleared = session.messages.length;
    session.messages.length = 0;
    return cleared;
  }

  clearMessageRange(sessionId: string, offset: number, count: number): number {
    const session = this.sessions.get(sessionId);
    if (!session) return 0;
    if (count <= 0) return 0;

    const start = Math.max(0, Math.min(offset, session.messages.length));
    const size = Math.max(0, Math.min(count, session.messages.length - start));
    if (size === 0) return 0;

    session.messages.splice(start, size);
    return size;
  }

  drainMessages(sessionId: string): ScriptMessage[] {
    const msgs = this.peekMessages(sessionId);
    this.clearMessages(sessionId);
    return msgs;
  }
}

// Singleton
export const sessionManager = new SessionManager();
