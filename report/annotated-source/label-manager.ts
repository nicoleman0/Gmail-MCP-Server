// =============================================================================
// ANNOTATED SOURCE: src/label-manager.ts — Gmail Label Management
// Security Audit — GongRzhe/Gmail-MCP-Server v1.1.11
// Date: 2026-02-22
//
// This file handles Gmail label CRUD operations.
// Annotations marked with [AUDIT] prefix. Finding IDs reference vulnerability-report.md.
//
// ASSESSMENT: This file has minimal direct security findings. Label operations are
// low-risk compared to email/filter operations. Included for completeness.
// =============================================================================

// Type definitions for Gmail API labels
export interface GmailLabel {
    id: string;
    name: string;
    type?: string;
    messageListVisibility?: string;
    labelListVisibility?: string;
    messagesTotal?: number;
    messagesUnread?: number;
    color?: {
        textColor?: string;
        backgroundColor?: string;
    };
}

export async function createLabel(gmail: any, labelName: string, options: {
    messageListVisibility?: string;
    labelListVisibility?: string;
} = {}) {
    // [AUDIT] INFO — Label creation is low-risk. Labels are metadata-only and do not
    // affect email content or routing. However, in a confused deputy context, label
    // creation could be used as part of a staging attack (create label -> filter to
    // label -> search by label -> exfiltrate via send_email).
    try {
        const messageListVisibility = options.messageListVisibility || 'show';
        const labelListVisibility = options.labelListVisibility || 'labelShow';

        const response = await gmail.users.labels.create({
            userId: 'me',
            requestBody: {
                name: labelName,
                messageListVisibility,
                labelListVisibility,
            },
        });

        return response.data;
    } catch (error: any) {
        if (error.message && error.message.includes('already exists')) {
            throw new Error(`Label "${labelName}" already exists. Please use a different name.`);
        }

        throw new Error(`Failed to create label: ${error.message}`);
    }
}

export async function updateLabel(gmail: any, labelId: string, updates: {
    name?: string;
    messageListVisibility?: string;
    labelListVisibility?: string;
}) {
    try {
        await gmail.users.labels.get({
            userId: 'me',
            id: labelId,
        });

        const response = await gmail.users.labels.update({
            userId: 'me',
            id: labelId,
            requestBody: updates,
        });

        return response.data;
    } catch (error: any) {
        if (error.code === 404) {
            throw new Error(`Label with ID "${labelId}" not found.`);
        }

        throw new Error(`Failed to update label: ${error.message}`);
    }
}

export async function deleteLabel(gmail: any, labelId: string) {
    // [AUDIT] INFO — deleteLabel includes a safety check for system labels (line 106-108
    // in original source), which is a positive security pattern. However, user labels can
    // still be deleted without confirmation. This is low-risk as label deletion does not
    // delete associated emails.
    try {
        const label = await gmail.users.labels.get({
            userId: 'me',
            id: labelId,
        });

        if (label.data.type === 'system') {
            throw new Error(`Cannot delete system label with ID "${labelId}".`);
        }

        await gmail.users.labels.delete({
            userId: 'me',
            id: labelId,
        });

        return { success: true, message: `Label "${label.data.name}" deleted successfully.` };
    } catch (error: any) {
        if (error.code === 404) {
            throw new Error(`Label with ID "${labelId}" not found.`);
        }

        throw new Error(`Failed to delete label: ${error.message}`);
    }
}

export async function listLabels(gmail: any) {
    try {
        const response = await gmail.users.labels.list({
            userId: 'me',
        });

        const labels = response.data.labels || [];

        const systemLabels = labels.filter((label:GmailLabel) => label.type === 'system');
        const userLabels = labels.filter((label:GmailLabel) => label.type === 'user');

        return {
            all: labels,
            system: systemLabels,
            user: userLabels,
            count: {
                total: labels.length,
                system: systemLabels.length,
                user: userLabels.length
            }
        };
    } catch (error: any) {
        throw new Error(`Failed to list labels: ${error.message}`);
    }
}

export async function findLabelByName(gmail: any, labelName: string) {
    try {
        const labelsResponse = await listLabels(gmail);
        const allLabels = labelsResponse.all;

        const foundLabel = allLabels.find(
            (label: GmailLabel) => label.name.toLowerCase() === labelName.toLowerCase()
        );

        return foundLabel || null;
    } catch (error: any) {
        throw new Error(`Failed to find label: ${error.message}`);
    }
}

export async function getOrCreateLabel(gmail: any, labelName: string, options: {
    messageListVisibility?: string;
    labelListVisibility?: string;
} = {}) {
    try {
        const existingLabel = await findLabelByName(gmail, labelName);

        if (existingLabel) {
            return existingLabel;
        }

        return await createLabel(gmail, labelName, options);
    } catch (error: any) {
        throw new Error(`Failed to get or create label: ${error.message}`);
    }
}
