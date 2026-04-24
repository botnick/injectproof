// InjectProof — Notification senders
// Delivers scan/finding events to the outbound channels configured via the
// NotificationConfig Prisma model (email/slack/discord/teams/webhook).
// Each backend is a small function accepting a `NotificationPayload`;
// `dispatch()` picks the right one per channel.
//
// No external dependencies — every channel is a fetch() call to a webhook.
// Email would require SMTP; omitted here since the common enterprise setup
// routes email through one of the messaging webhooks.

export type NotificationChannel = 'slack' | 'discord' | 'teams' | 'webhook' | 'email';

export interface NotificationPayload {
    title: string;
    body: string;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    context?: Record<string, string | number>;
    /** Link back to the finding / scan page. */
    link?: string;
}

export interface NotificationTarget {
    channel: NotificationChannel;
    /** Webhook URL for slack/discord/teams/webhook. For email, the "to" address. */
    endpoint: string;
    /** Optional shared secret for HMAC-signed webhook deliveries. */
    signingSecret?: string;
}

// ============================================================
// Formatters
// ============================================================

const SEVERITY_COLOR: Record<Required<NotificationPayload>['severity'], string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#d97706',
    low: '#2563eb',
    info: '#6b7280',
};

function slackPayload(p: NotificationPayload): Record<string, unknown> {
    const color = p.severity ? SEVERITY_COLOR[p.severity] : '#6366f1';
    return {
        text: p.title,
        attachments: [
            {
                color,
                title: p.title,
                text: p.body,
                title_link: p.link,
                fields: p.context
                    ? Object.entries(p.context).map(([title, value]) => ({ title, value: String(value), short: true }))
                    : [],
            },
        ],
    };
}

function discordPayload(p: NotificationPayload): Record<string, unknown> {
    return {
        username: 'InjectProof',
        embeds: [
            {
                title: p.title,
                description: p.body,
                color: parseInt((p.severity ? SEVERITY_COLOR[p.severity] : '#6366f1').slice(1), 16),
                url: p.link,
                fields: p.context
                    ? Object.entries(p.context).map(([name, value]) => ({ name, value: String(value), inline: true }))
                    : undefined,
                timestamp: new Date().toISOString(),
            },
        ],
    };
}

function teamsPayload(p: NotificationPayload): Record<string, unknown> {
    return {
        '@type': 'MessageCard',
        '@context': 'https://schema.org/extensions',
        themeColor: (p.severity ? SEVERITY_COLOR[p.severity] : '#6366f1').replace('#', ''),
        summary: p.title,
        sections: [
            {
                activityTitle: p.title,
                text: p.body,
                facts: p.context
                    ? Object.entries(p.context).map(([name, value]) => ({ name, value: String(value) }))
                    : [],
            },
        ],
        potentialAction: p.link
            ? [
                {
                    '@type': 'OpenUri',
                    name: 'View in InjectProof',
                    targets: [{ os: 'default', uri: p.link }],
                },
            ]
            : undefined,
    };
}

function genericWebhookPayload(p: NotificationPayload): Record<string, unknown> {
    return { ...p, emittedAt: new Date().toISOString() };
}

// ============================================================
// Dispatch
// ============================================================

export interface DispatchResult {
    ok: boolean;
    channel: NotificationChannel;
    status?: number;
    error?: string;
}

export async function dispatch(target: NotificationTarget, payload: NotificationPayload): Promise<DispatchResult> {
    if (target.channel === 'email') {
        return {
            ok: false,
            channel: 'email',
            error: 'email transport is not configured — route via webhook/slack/discord/teams for now',
        };
    }

    let body: Record<string, unknown>;
    switch (target.channel) {
        case 'slack': body = slackPayload(payload); break;
        case 'discord': body = discordPayload(payload); break;
        case 'teams': body = teamsPayload(payload); break;
        case 'webhook': body = genericWebhookPayload(payload); break;
    }

    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (target.signingSecret) {
        const { createHmac } = await import('node:crypto');
        const sig = createHmac('sha256', target.signingSecret).update(JSON.stringify(body)).digest('hex');
        headers['x-injectproof-signature'] = `sha256=${sig}`;
    }

    try {
        const res = await fetch(target.endpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(10_000),
        });
        return { ok: res.ok, channel: target.channel, status: res.status };
    } catch (err) {
        return {
            ok: false,
            channel: target.channel,
            error: err instanceof Error ? err.message : String(err),
        };
    }
}

/** Fan out to many targets, continuing on per-channel failure. */
export async function dispatchMany(
    targets: NotificationTarget[],
    payload: NotificationPayload,
): Promise<DispatchResult[]> {
    return Promise.all(targets.map((t) => dispatch(t, payload)));
}
