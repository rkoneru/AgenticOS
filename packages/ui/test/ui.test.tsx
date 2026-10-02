import { render, screen, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "jest-axe";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  Badge,
  Button,
  CodeEditor,
  Dialog,
  DiffView,
  EmptyState,
  ErrorBoundary,
  Input,
  Select,
  Table,
  Tabs,
  Textarea,
  Timeline,
  ToastProvider,
  cn,
  diffLines,
  useToast,
} from "../src/index";

describe("cn", () => {
  it("drops falsy parts", () => expect(cn("a", false, null, undefined, "b")).toBe("a b"));
});

describe("diffLines", () => {
  it("marks adds and deletes", () => {
    expect(diffLines("a\nb\nc", "a\nx\nc")).toEqual([
      { kind: "same", text: "a" },
      { kind: "del", text: "b" },
      { kind: "add", text: "x" },
      { kind: "same", text: "c" },
    ]);
  });
  it("handles empty sides and trailing runs", () => {
    expect(diffLines("", "a")).toEqual([{ kind: "add", text: "a" }]);
    expect(diffLines("a", "")).toEqual([{ kind: "del", text: "a" }]);
    expect(diffLines("a\nb", "a")).toEqual([
      { kind: "same", text: "a" },
      { kind: "del", text: "b" },
    ]);
  });
  it("falls back for very large inputs", () => {
    const big = Array.from({ length: 2001 }, (_, i) => String(i)).join("\n");
    const ops = diffLines(big, "x");
    expect(ops.filter((o) => o.kind === "del")).toHaveLength(2001);
  });
});

describe("components", () => {
  it("Button is clickable, loading disables it", async () => {
    const onClick = vi.fn();
    const { rerender } = render(<Button onClick={onClick}>Go</Button>);
    await userEvent.click(screen.getByRole("button", { name: "Go" }));
    expect(onClick).toHaveBeenCalledTimes(1);
    rerender(
      <Button loading onClick={onClick}>
        Go
      </Button>,
    );
    expect(screen.getByRole("button")).toBeDisabled();
    expect(screen.getByRole("button")).toHaveAttribute("aria-busy", "true");
  });

  it("fields wire label, hint and error", () => {
    render(
      <div>
        <Input label="Name" hint="Your name" error="Required" />
        <Textarea label="Notes" />
        <Select label="Role" options={[{ value: "a", label: "A" }]} />
      </div>,
    );
    const input = screen.getByLabelText("Name");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input.getAttribute("aria-describedby")).toMatch(/hint.*err/);
    expect(screen.getByRole("alert")).toHaveTextContent("Required");
    expect(screen.getByLabelText("Role")).toBeInTheDocument();
    expect(screen.getByLabelText("Notes")).toBeInTheDocument();
  });

  it("Table escapes untrusted text and shows empty state", () => {
    const payload = '<img src=x onerror="window.__xss=1">';
    const { container, rerender } = render(
      <Table
        caption="t"
        columns={[{ key: "a", header: "A", render: (r: { a: string }) => r.a }]}
        rows={[{ a: payload }]}
        rowKey={(r) => r.a}
      />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(payload)).toBeInTheDocument();
    rerender(
      <Table
        caption="t"
        columns={[]}
        rows={[]}
        rowKey={() => "k"}
        empty={<EmptyState title="Nothing" description="d" action={<button>x</button>} />}
      />,
    );
    expect(screen.getByText("Nothing")).toBeInTheDocument();
  });

  it("Dialog traps labelled content and closes on Escape", async () => {
    const Host = () => {
      const [o, setO] = useState(true);
      return (
        <Dialog
          open={o}
          onOpenChange={setO}
          title="Confirm"
          description="Sure?"
          footer={<Button>OK</Button>}
        >
          body
        </Dialog>
      );
    };
    render(<Host />);
    expect(screen.getByRole("dialog", { name: "Confirm" })).toBeInTheDocument();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Dialog without description", () => {
    render(
      <Dialog open onOpenChange={() => undefined} title="T">
        x
      </Dialog>,
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("Tabs switch with keyboard", async () => {
    render(
      <Tabs
        label="sections"
        items={[
          { value: "a", label: "A", content: <p>one</p> },
          { value: "b", label: "B", content: <p>two</p> },
        ]}
      />,
    );
    expect(screen.getByText("one")).toBeVisible();
    await userEvent.click(screen.getByRole("tab", { name: "B" }));
    expect(screen.getByText("two")).toBeVisible();
  });

  it("Toast announces and dismisses", async () => {
    const Host = () => {
      const t = useToast();
      return (
        <>
          <button onClick={() => t.push("saved", "success")}>s</button>
          <button onClick={() => t.push("boom", "error")}>e</button>
        </>
      );
    };
    render(
      <ToastProvider>
        <Host />
      </ToastProvider>,
    );
    await userEvent.click(screen.getByText("s"));
    await userEvent.click(screen.getByText("e"));
    expect(screen.getByRole("status")).toHaveTextContent("saved");
    expect(screen.getByRole("alert")).toHaveTextContent("boom");
    await userEvent.click(screen.getAllByLabelText("Dismiss notification")[0]!);
    expect(screen.queryByText("saved")).toBeNull();
  });

  it("CodeEditor reports edits and flags diagnostic lines", () => {
    const onChange = vi.fn();
    const { container } = render(
      <CodeEditor
        label="ABL"
        value={"a: 1\nb: 2"}
        onChange={onChange}
        markers={[
          { line: 2, column: 3, message: "bad <b>x</b>", severity: "error" },
          { line: 2, column: 1, message: "meh", severity: "warning" },
          { line: 1, column: 1, message: "w", severity: "warning" },
        ]}
      />,
    );
    fireEvent.change(screen.getByLabelText("ABL"), { target: { value: "z" } });
    expect(onChange).toHaveBeenCalledWith("z");
    expect(container.querySelector('[data-line="2"]')).toHaveAttribute("data-severity", "error");
    expect(container.querySelector('[data-line="1"]')).toHaveAttribute("data-severity", "warning");
    expect(container.querySelector("b")).toBeNull();
    expect(screen.getByText(/bad <b>x<\/b>/)).toBeInTheDocument();
  });

  it("Timeline marks the active item", () => {
    render(
      <Timeline
        label="events"
        activeId="2"
        items={[
          { id: "1", title: "one", at: "t", detail: "d", tone: "good" },
          { id: "2", title: "two", tone: "bad" },
          { id: "3", title: "three", tone: "warn" },
          { id: "4", title: "four" },
        ]}
      />,
    );
    expect(screen.getByText("two").closest("li")).toHaveAttribute("aria-current", "step");
  });

  it("DiffView shows adds, deletes, and the no-diff message", () => {
    const { rerender } = render(<DiffView label="d" before={"a\nb"} after={"a\nc"} />);
    expect(screen.getByText(/removed:/)).toBeInTheDocument();
    expect(screen.getByText(/added:/)).toBeInTheDocument();
    rerender(<DiffView label="d" before="a" after="a" />);
    expect(screen.getByText("No differences.")).toBeInTheDocument();
  });

  it("ErrorBoundary contains a crash and can retry", async () => {
    let crash = true;
    const Bomb = () => {
      if (crash) throw new Error("x");
      return <p>fine</p>;
    };
    const onError = vi.fn();
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    render(
      <ErrorBoundary onError={onError}>
        <Bomb />
      </ErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toBeInTheDocument();
    expect(onError).toHaveBeenCalled();
    crash = false;
    await act(async () => {
      await userEvent.click(screen.getByText("Try again"));
    });
    expect(screen.getByText("fine")).toBeInTheDocument();
    spy.mockRestore();
  });
});

describe("accessibility (axe)", () => {
  it("has no violations across the kit", async () => {
    const { container } = render(
      <main>
        <h1>Kit</h1>
        <Button>Save</Button>
        <Input label="Name" error="Required" />
        <Select label="Role" options={[{ value: "a", label: "A" }]} />
        <Badge tone="good">ok</Badge>
        <Table
          caption="rows"
          columns={[{ key: "a", header: "A", render: (r: { a: string }) => r.a }]}
          rows={[{ a: "x" }]}
          rowKey={(r) => r.a}
        />
        <CodeEditor
          label="Code"
          value="a"
          onChange={() => undefined}
          markers={[{ line: 1, column: 1, message: "m", severity: "error" }]}
        />
        <Timeline label="tl" items={[{ id: "1", title: "t" }]} />
        <DiffView label="diff" before="a" after="b" />
        <EmptyState title="Empty" />
      </main>,
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
