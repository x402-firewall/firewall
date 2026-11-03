import { logger } from './logger.js';

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

  try {
    const isDiscord = webhookUrl.includes('discord.com/api/webhooks');
    const body = isDiscord
      ? {
          content: `🚨 **[x402Firewall Alert] ${payload.event}**\n` +
            `• **Reason:** ${payload.reason}\n` +
            `• **Amount:** ${payload.amountUsdc !== undefined ? `$${payload.amountUsdc.toFixed(4)} USDC` : 'N/A'}\n` +
            `• **Recipient:** \`${payload.recipient || 'N/A'}\`\n` +
            `• **Domain:** \`${payload.domain || 'N/A'}\`\n` +
            `• **Time:** ${payload.timestamp}`,
        }
      : payload;

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

