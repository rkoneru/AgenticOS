import { Component, type ErrorInfo, type ReactNode } from "react";

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<
  { children: ReactNode; onError?: (e: Error, info: ErrorInfo) => void },
  State
> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    this.props.onError?.(error, info);
  }

  override render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div role="alert" className="rounded-md border border-[var(--axis-danger)] p-4">
        <h2 className="font-semibold">Something went wrong</h2>
        <p className="text-sm text-[var(--axis-muted)]">
          This section failed to render. The rest of the page still works.
        </p>
        <button
          type="button"
          className="mt-2 rounded-md border border-[var(--axis-border)] px-3 py-1 text-sm"
          onClick={() => this.setState({ error: null })}
        >
          Try again
        </button>
      </div>
    );
  }
}
