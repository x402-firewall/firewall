import { z } from 'zod';
import type { FirewallClient } from '../../client.js';

export const FirewallFetchToolInputSchema = z.object({
  url: z.string().url({ message: 'Must be a valid HTTP or HTTPS URL' }),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).default('GET'),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().optional(),
});

export type FirewallFetchToolInput = z.infer<typeof FirewallFetchToolInputSchema>;

// Aliases
export const GuardedFetchToolInputSchema = FirewallFetchToolInputSchema;
export type GuardedFetchToolInput = FirewallFetchToolInput;

export const firewallFetchToolDefinition = {
  name: 'x402_fetch',
  description:
    'Safely fetch free or x402-paid HTTP endpoints with deterministic spending caps and automatic EIP-3009 payment authorization on Base L2.',
  inputSchema: {
    type: 'object',
    properties: {
      url: {
        type: 'string',
        description: 'Target endpoint URL (e.g., https://api.weather.com/v1/forecast or paid x402 resource)',
      },
      method: {
        type: 'string',
        enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        default: 'GET',
        description: 'HTTP method (default: GET)',
      },
      headers: {
        type: 'object',
        additionalProperties: { type: 'string' },
        description: 'Optional custom HTTP headers',
      },
      body: {
        type: 'string',
        description: 'Optional HTTP request body (e.g., JSON string)',
      },
    },
    required: ['url'],
  },
};

export const guardedFetchToolDefinition = firewallFetchToolDefinition;

export async function handleFirewallFetchTool(
  client: FirewallClient,
  args: unknown
) {
  const parsed = FirewallFetchToolInputSchema.parse(args);

  try {
    const response = await client.fetch(parsed.url, {
      method: parsed.method,
      headers: parsed.headers as Record<string, string> | undefined,
      body: parsed.body,
    });

    const contentType = response.headers.get('content-type') || '';
    const text = await response.text();

    let formattedBody: unknown = text;
    if (contentType.includes('application/json')) {
      try {
        formattedBody = JSON.parse(text);
      } catch {
        // Fall back to raw string
      }
    }

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              status: response.status,
              statusText: response.statusText,
              headers: responseHeaders,
              body: formattedBody,
            },
            null,
            2
          ),
        },
      ],
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `[x402Firewall Error] ${message}`,
        },
      ],
    };
  }
}

export const handleGuardedFetchTool = handleFirewallFetchTool;

