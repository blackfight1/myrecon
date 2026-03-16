import { Component, type ReactNode } from "react";
import { WORKSPACE_ACTIVE_PROJECT_KEY } from "../../context/WorkspaceContext";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  message: string;
}

export class AppErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      message: ""
    };
  }

  static getDerivedStateFromError(error: unknown): State {
    const message = error instanceof Error ? error.message : String(error);
    return {
      hasError: true,
      message
    };
  }

  componentDidCatch(error: unknown): void {
    // Keep a concise log to help debugging runtime crashes in production.
    console.error("[AppErrorBoundary] runtime error:", error);
  }

  private handleReset = () => {
    try {
      window.localStorage.removeItem(WORKSPACE_ACTIVE_PROJECT_KEY);
      window.localStorage.removeItem("myrecon.workspace.v1");
    } catch {
      // Ignore storage exceptions.
    }
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <section style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "#0a0e1a", color: "#e2e8f0", padding: 24 }}>
          <div style={{ maxWidth: 720, width: "100%", border: "1px solid rgba(255,255,255,0.14)", borderRadius: 12, padding: 20, background: "rgba(17,24,39,0.9)" }}>
            <h1 style={{ fontSize: 20, margin: 0 }}>Frontend Runtime Error</h1>
            <p style={{ marginTop: 10, color: "#94a3b8" }}>
              页面出现运行时错误，已阻止黑屏。你可以先清理本地项目缓存后重试。
            </p>
            <pre style={{ marginTop: 12, whiteSpace: "pre-wrap", wordBreak: "break-word", background: "rgba(0,0,0,0.35)", borderRadius: 8, padding: 12, color: "#fca5a5" }}>
{this.state.message || "Unknown error"}
            </pre>
            <div style={{ marginTop: 14, display: "flex", gap: 10 }}>
              <button type="button" onClick={this.handleReset} style={{ border: "1px solid #3b82f6", background: "transparent", color: "#93c5fd", borderRadius: 8, padding: "8px 12px" }}>
                Clear Workspace Cache & Reload
              </button>
              <button type="button" onClick={() => window.location.reload()} style={{ border: "1px solid rgba(255,255,255,0.2)", background: "transparent", color: "#e2e8f0", borderRadius: 8, padding: "8px 12px" }}>
                Reload
              </button>
            </div>
          </div>
        </section>
      );
    }

    return this.props.children;
  }
}
