import { z } from 'zod';
import type { FirewallClient } from '../../client.js';

export const AuditLogInputSchema = z.object({
  limit: z.number().int().positive().max(100).default(20),
  status: z.enum(['ALLOWED', 'BLOCKED', 'ALL']).default('ALL'),
});

export type AuditLogInput = z.infer<typeof AuditLogInputSchema>;

export const auditLogToolDefinition = {
  name: 'x402_audit_log',
  description:
    'Inspect recent permitted and blocked transactions/payments in the local SQLite audit log.',
  inputSchema: {
    type: 'object',
    properties: {
      limit: {
        type: 'number',
        default: 20,
        description: 'Maximum number of recent records to return (1-100)',
      },
      status: {
        type: 'string',
        enum: ['ALLOWED', 'BLOCKED', 'ALL'],
        default: 'ALL',
        description: 'Filter logs by status: ALLOWED, BLOCKED, or ALL',
      },
    },
  },
};

export async function handleAuditLogTool(
  client: FirewallClient,
  args: unknown
) {
  const parsed = AuditLogInputSchema.parse(args || {});
  const statusFilter = parsed.status === 'ALL' ? undefined : parsed.status;

  const logs = client.getAuditLogs(parsed.limit, statusFilter);

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            total: logs.length,
            statusFilter: parsed.status,
            logs,
          },
          null,
          2
        ),
      },
    ],
  };
}

