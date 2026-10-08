import { useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";

/** Native dialog supplies keyboard focus containment; restore focus on dismissal. */
export function AppDialog({
  title,
  children,
  onClose,
  busy = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null),
    id = useId(),
    trigger = useRef<HTMLElement | null>(null);
  useEffect(() => {
    trigger.current = document.activeElement as HTMLElement;
    ref.current?.showModal();
    return () => {
      trigger.current?.focus();
    };
  }, []);
  return (
    <dialog
      className="ui-dialog"
      ref={ref}
      aria-labelledby={id}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) onClose();
      }}
    >
      <header>
        <h2 id={id}>{title}</h2>
        <button
          type="button"
          disabled={busy}
          aria-label="关闭对话框"
          onClick={onClose}
        >
          ×
        </button>
      </header>
      {children}
    </dialog>
  );
}
export function ConfirmDialog({
  title,
  children,
  action = "确认",
  busy,
  onConfirm,
  onClose,
}: {
  title: string;
  children: ReactNode;
  action?: string;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <AppDialog title={title} onClose={onClose} busy={busy}>
      <div className="ui-dialog-body">{children}</div>
      <footer>
        <button disabled={busy} onClick={onClose}>
          取消
        </button>
        <button className="ui-primary" disabled={busy} onClick={onConfirm}>
          {busy ? "处理中…" : action}
        </button>
      </footer>
    </AppDialog>
  );
}
export function LoadingState({ label = "正在加载…" }: { label?: string }) {
  return (
    <div className="ui-loading" role="status" aria-live="polite">
      <span className="ui-spinner" />
      <h2>{label}</h2>
      <p>请稍候，操作完成后会显示最新结果。</p>
      <div className="ui-skeleton" />
      <div className="ui-skeleton" />
    </div>
  );
}
export function Icon({ kind = "grid" }: { kind?: string }) {
  const d: Record<string, string> = {
    grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    sample: "M6 3h9l4 4v14H6zM14 3v5h5M9 12h7M9 16h7",
    host: "M3 4h18v12H3zM8 21h8M12 16v5",
    history: "M4 5h16v16H4zM8 2v6M16 2v6M8 12h8M8 16h5",
    settings:
      "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2",
  };
  return (
    <svg
      className="ui-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={d[kind] || d.grid} />
    </svg>
  );
}
/** Guard dismissals without a native browser confirmation. */
export function useDiscardGuard(dirty: boolean) {
  const [pending, setPending] = useState<(() => void) | null>(null);
  return {
    request: (fn: () => void) => (dirty ? setPending(() => fn) : fn()),
    dialog: pending ? (
      <ConfirmDialog
        title="放弃未保存的修改？"
        action="放弃修改"
        onClose={() => setPending(null)}
        onConfirm={() => {
          pending();
          setPending(null);
        }}
      >
        <p>离开后，本次尚未保存的编辑将丢失。</p>
      </ConfirmDialog>
    ) : null,
  };
}
