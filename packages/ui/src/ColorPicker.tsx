import {
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
} from 'react';

import { formatHex, hsvToRgb, normalizeHex, parseHex, rgbToHsv, type Hsva } from './theme/color.js';

export interface ColorPickerProps {
  value: string;
  onChange: (hex: string) => void;
  /** Hide the alpha slider for roles that must stay opaque. */
  alpha?: boolean;
  /** Colours offered as one-click swatches (current theme, recent picks). */
  swatches?: readonly string[];
  label?: string;
}

interface EyeDropperCtor {
  new (): { open: () => Promise<{ sRGBHex: string }> };
}

function eyeDropper(): EyeDropperCtor | null {
  const w = globalThis as unknown as { EyeDropper?: EyeDropperCtor };
  return typeof w.EyeDropper === 'function' ? w.EyeDropper : null;
}

const clamp01 = (n: number) => Math.min(1, Math.max(0, n));

function toHsv(hex: string): Hsva {
  return rgbToHsv(parseHex(hex) ?? { r: 0, g: 0, b: 0, a: 1 });
}

/**
 * Full-spectrum picker: saturation/value field, hue and alpha rails, a hex
 * field and the platform eyedropper where one exists. HSV is held locally so
 * dragging through grey does not lose the hue the user was on.
 */
export function ColorPicker({
  value,
  onChange,
  alpha = true,
  swatches = [],
  label = 'colour',
}: ColorPickerProps) {
  const [hsv, setHsv] = useState<Hsva>(() => toHsv(value));
  const [text, setText] = useState(value);
  const lastEmitted = useRef(value);

  useEffect(() => {
    if (value === lastEmitted.current) return;
    lastEmitted.current = value;
    setHsv(toHsv(value));
    setText(value);
  }, [value]);

  const emit = (next: Hsva) => {
    const n = alpha ? next : { ...next, a: 1 };
    setHsv(n);
    const hex = formatHex(hsvToRgb(n));
    lastEmitted.current = hex;
    setText(hex);
    onChange(hex);
  };

  const hueColor = formatHex(hsvToRgb({ h: hsv.h, s: 1, v: 1, a: 1 }));
  const opaque = formatHex(hsvToRgb({ ...hsv, a: 1 }));
  const Dropper = eyeDropper();

  return (
    <div className="flex w-[232px] flex-col gap-2 p-2" role="group" aria-label={label}>
      <Field2D hue={hueColor} s={hsv.s} v={hsv.v} onChange={(s, v) => emit({ ...hsv, s, v })} />
      <Rail
        label="hue"
        value={hsv.h / 360}
        background="linear-gradient(90deg,#f00 0%,#ff0 16.66%,#0f0 33.33%,#0ff 50%,#00f 66.66%,#f0f 83.33%,#f00 100%)"
        onChange={(t) => emit({ ...hsv, h: t * 360 })}
        valueText={`${Math.round(hsv.h)}°`}
      />
      {alpha && (
        <Rail
          label="opacity"
          value={hsv.a}
          checker
          background={`linear-gradient(90deg, transparent, ${opaque})`}
          onChange={(t) => emit({ ...hsv, a: t })}
          valueText={`${Math.round(hsv.a * 100)}%`}
        />
      )}
      <div className="flex items-center gap-1.5">
        <span
          aria-hidden
          className="sw-checker h-6 w-6 flex-none rounded-sw-sm border border-edge"
          style={{ ['--swatch' as string]: formatHex(hsvToRgb(hsv)) }}
        />
        <input
          className="h-6 min-w-0 flex-1 rounded-sw-sm border border-edge bg-paper px-1.5 font-mono text-[11px] text-ink outline-none focus:border-edge-strong"
          value={text}
          spellCheck={false}
          aria-label={`${label} hex`}
          onChange={(e) => {
            setText(e.target.value);
            const n = normalizeHex(e.target.value);
            if (n) {
              const next = toHsv(n);
              setHsv(alpha ? next : { ...next, a: 1 });
              const out = alpha ? n : formatHex({ ...parseHex(n)!, a: 1 });
              lastEmitted.current = out;
              onChange(out);
            }
          }}
          onBlur={() => setText(lastEmitted.current)}
        />
        {Dropper && (
          <button
            type="button"
            className="sw-pressable inline-flex h-6 w-6 flex-none items-center justify-center rounded-sw-sm border border-edge text-muted"
            title="pick from screen"
            aria-label="pick from screen"
            onClick={() => {
              new Dropper()
                .open()
                .then((r) => {
                  const n = normalizeHex(r.sRGBHex);
                  if (n) emit({ ...toHsv(n), a: hsv.a });
                })
                .catch(() => undefined);
            }}
          >
            <svg width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden>
              <path
                d="M7.5 2.5l2 2M8.5 1.5a1.4 1.4 0 0 1 2 2L9 5 7 3zM7 3 2 8l-.5 2.5L4 10l5-5"
                stroke="currentColor"
                strokeWidth="1.1"
                strokeLinejoin="round"
              />
            </svg>
          </button>
        )}
      </div>
      {swatches.length > 0 && (
        <div className="flex flex-wrap gap-1" aria-label="swatches">
          {swatches.map((s, i) => (
            <button
              key={`${s}-${i}`}
              type="button"
              className="sw-checker sw-pressable h-4 w-4 rounded-[3px] border border-edge"
              style={{ ['--swatch' as string]: s }}
              title={s}
              aria-label={`use ${s}`}
              onClick={() => {
                const n = normalizeHex(s);
                if (n) emit(toHsv(n));
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function usePointerDrag(onPoint: (x: number, y: number) => void) {
  const ref = useRef<HTMLDivElement>(null);
  const handle = (e: ReactPointerEvent<HTMLDivElement>) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    onPoint(clamp01((e.clientX - r.left) / r.width), clamp01((e.clientY - r.top) / r.height));
  };
  return {
    ref,
    onPointerDown: (e: ReactPointerEvent<HTMLDivElement>) => {
      e.currentTarget.setPointerCapture(e.pointerId);
      handle(e);
    },
    onPointerMove: (e: ReactPointerEvent<HTMLDivElement>) => {
      if (e.currentTarget.hasPointerCapture(e.pointerId)) handle(e);
    },
  };
}

function Field2D({
  hue,
  s,
  v,
  onChange,
}: {
  hue: string;
  s: number;
  v: number;
  onChange: (s: number, v: number) => void;
}) {
  const drag = usePointerDrag((x, y) => onChange(x, 1 - y));
  const onKey = (e: KeyboardEvent) => {
    const step = e.shiftKey ? 0.1 : 0.01;
    const moves: Record<string, [number, number]> = {
      ArrowLeft: [-step, 0],
      ArrowRight: [step, 0],
      ArrowUp: [0, step],
      ArrowDown: [0, -step],
    };
    const m = moves[e.key];
    if (!m) return;
    e.preventDefault();
    onChange(clamp01(s + m[0]), clamp01(v + m[1]));
  };
  return (
    <div
      {...drag}
      role="slider"
      tabIndex={0}
      aria-label="saturation and brightness"
      aria-valuetext={`saturation ${Math.round(s * 100)}%, brightness ${Math.round(v * 100)}%`}
      onKeyDown={onKey}
      className="relative h-[140px] w-full cursor-crosshair touch-none rounded-sw-sm border border-edge outline-none focus-visible:border-edge-strong"
      style={{
        background: `linear-gradient(to top, #000, transparent), linear-gradient(to right, #fff, ${hue})`,
      }}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-white shadow-[0_0_0_1px_rgb(0_0_0/0.6)]"
        style={{ left: `${s * 100}%`, top: `${(1 - v) * 100}%` }}
      />
    </div>
  );
}

function Rail({
  label,
  value,
  background,
  checker,
  valueText,
  onChange,
}: {
  label: string;
  value: number;
  background: string;
  checker?: boolean;
  valueText: string;
  onChange: (t: number) => void;
}) {
  const drag = usePointerDrag((x) => onChange(x));
  const onKey = (e: KeyboardEvent) => {
    const step = e.shiftKey ? 0.1 : 0.01;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') onChange(clamp01(value - step));
    else if (e.key === 'ArrowRight' || e.key === 'ArrowUp') onChange(clamp01(value + step));
    else if (e.key === 'Home') onChange(0);
    else if (e.key === 'End') onChange(1);
    else return;
    e.preventDefault();
  };
  return (
    <div
      {...drag}
      role="slider"
      tabIndex={0}
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(value * 100)}
      aria-valuetext={valueText}
      onKeyDown={onKey}
      className={`relative h-3 w-full cursor-pointer touch-none rounded-full border border-edge outline-none focus-visible:border-edge-strong ${checker ? 'sw-checker' : ''}`}
    >
      <span aria-hidden className="absolute inset-0 rounded-full" style={{ background }} />
      <span
        aria-hidden
        className="pointer-events-none absolute top-1/2 h-3.5 w-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-white shadow-[0_0_0_1px_rgb(0_0_0/0.6)]"
        style={{ left: `${value * 100}%` }}
      />
    </div>
  );
}
