import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { FirewallClient } from '../client.js';
import {
  firewallFetchToolDefinition,
  handleFirewallFetchTool,
} from './tools/firewallFetchTool.js';
import {
  budgetStatusToolDefinition,
  handleBudgetStatusTool,
} from './tools/budgetStatusTool.js';
import {
  executeSafeTxToolDefinition,
  handleExecuteSafeTxTool,
} from './tools/executeSafeTxTool.js';
import {
  auditLogToolDefinition,
  handleAuditLogTool,
} from './tools/auditLogTool.js';
import { logger } from '../utils/logger.js';

export function createMcpServer(client?: FirewallClient) {
  const firewallClient = client || new FirewallClient();

  const server = new Server(
    {
      name: 'x402-firewall',
      version: '0.1.3',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Register tools list
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        firewallFetchToolDefinition,
        budgetStatusToolDefinition,
        executeSafeTxToolDefinition,
        auditLogToolDefinition,
      ],
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    logger.debug('MCP tool called', { name });

    switch (name) {
      case 'x402_fetch':
        return handleFirewallFetchTool(firewallClient, args);

      case 'x402_get_budget':
        return handleBudgetStatusTool(firewallClient);

      case 'x402_safe_tx':
      case 'x402_simulate_and_send_tx':
        return handleExecuteSafeTxTool(firewallClient, args);

      case 'x402_audit_log':
        return handleAuditLogTool(firewallClient, args);

      default:
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Unknown tool name: ${name}`,
            },
          ],
        };
    }
  });

  return {
    server,
    client: firewallClient,
    start: async () => {
      const transport = new StdioServerTransport();
      await server.connect(transport);
      // NOTE: Strictly write info to stderr so stdout is reserved for MCP JSON-RPC
      logger.info('x402Firewall MCP Server running on stdio');
    },
  };
}
