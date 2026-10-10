import type { ComponentType, ReactNode } from 'react';

import type { ElementKind, Pane, PaneProps } from '../schema.js';

/** One row in an element's settings popover. Controls map onto `pane.props[key]`. */
export type SettingField =
  | { key: string; label: string; help?: string; kind: 'toggle' }
  | {
      key: string;
      label: string;
      help?: string;
      kind: 'number';
      min?: number;
      max?: number;
      step?: number;
    }
  | {
      key: string;
      label: string;
      help?: string;
      kind: 'select';
      /** Static options, or a hook-free resolver run at render time against app state. */
      options:
        | readonly { value: string; label: string }[]
        | (() => readonly { value: string; label: string }[]);
    };

export interface ElementBodyProps {
  pane: Pane;
  /** Width and height of the body in CSS px, measured by the frame; 0 before first layout. */
  width: number;
  height: number;
  /** Merge-updates `pane.props`. */
  setProps: (props: PaneProps) => void;
}

export interface ElementDefinition {
  kind: ElementKind;
  title: string;
  /** One-line hint shown dimmed after the name in catalogues. */
  hint: string;
  defaultSize: { w: number; h: number };
  minSize?: { w: number; h: number };
  defaultProps?: PaneProps;
  settings?: readonly SettingField[];
  /** Scope chips rendered in the title row after the name (wallet name, chain, range …). */
  scope?: (pane: Pane) => readonly { label: string; tone?: 'warm' | 'default' }[];
  /** Dynamic title override, e.g. the wallet's name. */
  titleFor?: (pane: Pane) => string;
  body: ComponentType<ElementBodyProps>;
  /** Extra title-row controls (pause, timeframe …). */
  toolbar?: ComponentType<ElementBodyProps>;
}

export type ElementRegistry = Readonly<Record<ElementKind, ElementDefinition>>;

export type RenderElement = (pane: Pane, size: { width: number; height: number }) => ReactNode;
