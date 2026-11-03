import { logger } from './logger.js';

export function isSafeExternalUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    // Block loopback, local, RFC1918, and cloud metadata (169.254.169.254) addresses
    if (
      host === 'localhost' ||
      host === '0.0.0.0' ||
      host === '::1' ||
      host.endsWith('.local') ||
      host.startsWith('127.') ||
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      host.startsWith('169.254.') ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export interface WebhookAlertPayload {
  event: 'POLICY_VIOLATION' | 'TRANSACTION_BLOCKED' | 'BUDGET_EXCEEDED';
  reason: string;
  amountUsdc?: number;
  recipient?: string;
  domain?: string;
  calldata?: string;
  timestamp: string;
}

export async function sendWebhookAlert(
  webhookUrl: string | undefined,
  payload: WebhookAlertPayload
): Promise<boolean> {
  if (!webhookUrl) {
    return false;
  }

  if (!isSafeExternalUrl(webhookUrl)) {
    logger.warn('SSRF protection blocked webhook dispatch to unsafe or internal URL', { webhookUrl });
    return false;
  }

  try {
    const isDiscord = webhookUrl.includes('discord.com/api/webhooks');
    const safePayload = {
      ...payload,
      calldata: payload.calldata ? (payload.calldata.length > 66 ? `${payload.calldata.slice(0, 66)}...[truncated]` : payload.calldata) : undefined,
    };
    const body = isDiscord
      ? {
          content: `🚨 **[x402Firewall Alert] ${payload.event}**\n` +
            `• **Reason:** ${payload.reason}\n` +
            `• **Amount:** ${payload.amountUsdc !== undefined ? `$${payload.amountUsdc.toFixed(4)} USDC` : 'N/A'}\n` +
            `• **Recipient:** \`${payload.recipient || 'N/A'}\`\n` +
            `• **Domain:** \`${payload.domain || 'N/A'}\`\n` +
            `• **Time:** ${payload.timestamp}`,
        }
      : safePayload;

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000), // 5s timeout
    });

    if (!response.ok) {
      logger.warn('Failed to send webhook alert', {
        status: response.status,
        statusText: response.statusText,
      });
      return false;
    }

    return true;
  } catch (error) {
    logger.warn('Error sending webhook alert', {
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}

