import { createAnthropic } from '@ai-sdk/anthropic';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { createOpenAI } from '@ai-sdk/openai';
import { createOpenRouter } from '@openrouter/ai-sdk-provider';
import type { LanguageModel } from 'ai';

/**
 * Bring-your-own-key cloud models (D4). Keys are sealed in the vault and
 * handed to the provider client only for a session; requests go straight
 * from this device to the provider, never through a StackWallet server.
 */
import type { ProviderId } from './catalog.js';

export { PROVIDERS, isProviderId, type ProviderId } from './catalog.js';

export function languageModel(
  provider: ProviderId,
  apiKey: string,
  modelId: string,
): LanguageModel {
  switch (provider) {
    case 'anthropic':
      return createAnthropic({
        apiKey,
        // Required for calls from a browser; the key never leaves this device otherwise.
        headers: { 'anthropic-dangerous-direct-browser-access': 'true' },
      })(modelId);
    case 'openai':
      return createOpenAI({ apiKey })(modelId);
    case 'google':
      return createGoogleGenerativeAI({ apiKey })(modelId);
    case 'openrouter':
      return createOpenRouter({ apiKey })(modelId) as unknown as LanguageModel;
  }
}
