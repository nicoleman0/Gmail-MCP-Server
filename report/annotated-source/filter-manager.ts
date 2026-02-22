// =============================================================================
// ANNOTATED SOURCE: src/filter-manager.ts — Gmail Filter Management
// Security Audit — GongRzhe/Gmail-MCP-Server v1.1.11
// Date: 2026-02-22
//
// This file handles Gmail filter CRUD operations.
// Annotations marked with [AUDIT] prefix. Finding IDs reference vulnerability-report.md.
// =============================================================================

// Type definitions for Gmail API filters
export interface GmailFilterCriteria {
    from?: string;
    to?: string;
    subject?: string;
    query?: string;
    negatedQuery?: string;
    hasAttachment?: boolean;
    excludeChats?: boolean;
    size?: number;
    sizeComparison?: 'unspecified' | 'smaller' | 'larger';
}

export interface GmailFilterAction {
    addLabelIds?: string[];
    removeLabelIds?: string[];
    forward?: string;
    // [AUDIT][F08][F09] HIGH — CD/II: The 'forward' field enables persistent email
    // forwarding to any address. No type-level restriction beyond string.
    // Combined with criteria.query: "in:anywhere", this can forward ALL future email.
    // Gmail API may enforce forwarding address verification, but:
    //   1. Label-based staging attacks remain fully exploitable
    //   2. Archive/hide attacks (removeLabelIds: ['INBOX']) work without forwarding
    //   3. If user has previously verified a forwarding address, filters can reuse it
}

export interface GmailFilter {
    id?: string;
    criteria: GmailFilterCriteria;
    action: GmailFilterAction;
}

export async function createFilter(gmail: any, criteria: GmailFilterCriteria, action: GmailFilterAction) {
    // [AUDIT][F08] HIGH — CD: This function creates Gmail filters with NO validation
    // beyond what the Gmail API enforces. There is:
    //   - No confirmation prompt before creating filters
    //   - No validation of the 'forward' email address
    //   - No restriction on criteria scope (can match all email)
    //   - No logging of filter creation beyond the return value
    //   - No allowlist for forwarding addresses
    //
    // Filters persist in Gmail (server-side), survive MCP server shutdown, and
    // operate silently with no per-email notification to the user.
    try {
        const filterBody: GmailFilter = {
            criteria,
            // [AUDIT] LOW — II: criteria.query is passed directly to Gmail API.
            // Gmail handles its own query parsing, but broad queries like "in:anywhere"
            // can match all email when combined with the forward action.
            action
            // [AUDIT][F09] HIGH — II: action.forward accepts any string with no
            // email format validation. The server relies entirely on Gmail API
            // for validation. FIX: Validate with validateEmail() at minimum,
            // or maintain an allowlist of approved forwarding addresses.
        };

        const response = await gmail.users.settings.filters.create({
            userId: 'me',
            requestBody: filterBody,
        });

        return response.data;
    } catch (error: any) {
        if (error.code === 400) {
            throw new Error(`Invalid filter criteria or action: ${error.message}`);
        }
        throw new Error(`Failed to create filter: ${error.message}`);
    }
}

export async function listFilters(gmail: any) {
    try {
        const response = await gmail.users.settings.filters.list({
            userId: 'me',
        });

        const filters = response.data.filters || [];

        return {
            filters,
            count: filters.length
        };
    } catch (error: any) {
        throw new Error(`Failed to list filters: ${error.message}`);
    }
}

export async function getFilter(gmail: any, filterId: string) {
    try {
        const response = await gmail.users.settings.filters.get({
            userId: 'me',
            id: filterId,
        });

        return response.data;
    } catch (error: any) {
        if (error.code === 404) {
            throw new Error(`Filter with ID "${filterId}" not found.`);
        }
        throw new Error(`Failed to get filter: ${error.message}`);
    }
}

export async function deleteFilter(gmail: any, filterId: string) {
    try {
        await gmail.users.settings.filters.delete({
            userId: 'me',
            id: filterId,
        });

        return { success: true, message: `Filter "${filterId}" deleted successfully.` };
    } catch (error: any) {
        if (error.code === 404) {
            throw new Error(`Filter with ID "${filterId}" not found.`);
        }
        throw new Error(`Failed to delete filter: ${error.message}`);
    }
}

export const filterTemplates = {
    fromSender: (senderEmail: string, labelIds: string[] = [], archive: boolean = false): { criteria: GmailFilterCriteria, action: GmailFilterAction } => ({
        criteria: { from: senderEmail },
        action: {
            addLabelIds: labelIds,
            removeLabelIds: archive ? ['INBOX'] : undefined
        }
    }),

    withSubject: (subjectText: string, labelIds: string[] = [], markAsRead: boolean = false): { criteria: GmailFilterCriteria, action: GmailFilterAction } => ({
        criteria: { subject: subjectText },
        action: {
            addLabelIds: labelIds,
            removeLabelIds: markAsRead ? ['UNREAD'] : undefined
        }
    }),

    withAttachments: (labelIds: string[] = []): { criteria: GmailFilterCriteria, action: GmailFilterAction } => ({
        criteria: { hasAttachment: true },
        action: { addLabelIds: labelIds }
    }),

    largeEmails: (sizeInBytes: number, labelIds: string[] = []): { criteria: GmailFilterCriteria, action: GmailFilterAction } => ({
        criteria: { size: sizeInBytes, sizeComparison: 'larger' },
        action: { addLabelIds: labelIds }
    }),

    containingText: (searchText: string, labelIds: string[] = [], markImportant: boolean = false): { criteria: GmailFilterCriteria, action: GmailFilterAction } => ({
        criteria: { query: `"${searchText}"` },
        // [AUDIT] LOW — II: searchText is interpolated into a query string with
        // double quotes. A carefully crafted searchText could potentially break out
        // of the quoted context, though Gmail's query parser is generally robust.
        action: {
            addLabelIds: markImportant ? [...labelIds, 'IMPORTANT'] : labelIds
        }
    }),

    mailingList: (listIdentifier: string, labelIds: string[] = [], archive: boolean = true): { criteria: GmailFilterCriteria, action: GmailFilterAction } => ({
        criteria: { query: `list:${listIdentifier} OR subject:[${listIdentifier}]` },
        action: {
            addLabelIds: labelIds,
            removeLabelIds: archive ? ['INBOX'] : undefined
            // [AUDIT] INFO — Archive action (removeLabelIds: ['INBOX']) hides emails
            // from the inbox. In a confused deputy context, this could be used to
            // silently hide emails from the user without forwarding them.
        }
    })
};
