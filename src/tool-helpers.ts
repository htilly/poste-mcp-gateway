import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

export const json = (value: unknown): CallToolResult => ({ content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] });
export const fail = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

export const folder = z.string().default('INBOX').describe('Mailbox folder path, as returned by list_folders. Defaults to INBOX.');
export const uid = z.coerce.number().int().positive().describe('Message UID from search_mail or read_thread.');
