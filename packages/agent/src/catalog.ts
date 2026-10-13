/** Provider catalogue, importable without the SDKs (they load with the first turn). */
export const PROVIDERS = [
  { id: 'anthropic', label: 'Anthropic', defaultModel: 'claude-sonnet-5-5' },
  { id: 'openai', label: 'OpenAI', defaultModel: 'gpt-5' },
  { id: 'google', label: 'Google', defaultModel: 'gemini-2.5-pro' },
  { id: 'openrouter', label: 'OpenRouter', defaultModel: 'anthropic/claude-sonnet-5.5' },
] as const;

export type ProviderId = (typeof PROVIDERS)[number]['id'];

export function isProviderId(v: unknown): v is ProviderId {
  return PROVIDERS.some((p) => p.id === v);
}
