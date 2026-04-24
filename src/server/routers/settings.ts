// InjectProof — Settings router
// =============================
// Wires the /settings page to real persistence. Before this router existed,
// the Settings UI was a dead-end — every field had defaultValue / defaultChecked
// with no onChange or submit handler. This router fixes that.
//
// What we persist here:
//  - Profile: the user's display name. Email + role stay read-only
//    (email change needs an audit trail + verification flow we haven't built;
//    role change belongs to admin user-management not self-service).
//  - Notification preferences: stored in the existing NotificationConfig
//    model as a single "email" channel row per user. We auto-create the row
//    on first read so the UI always has something to display.
//
// What we DO NOT persist:
//  - Scanner defaults (max depth / max URLs / rate limit). Those belong on
//    the Target model (and they already are). Settings is for user prefs;
//    scan configs are per-target.

import { z } from 'zod';
import { TRPCError } from '@trpc/server';
import { router, protectedProcedure } from '@/server/trpc';

// ── Event identifiers for notification prefs ──
// Kept short + stable so they can be reused in the notifier dispatcher.
const NOTIFY_EVENTS = {
    criticalVuln: 'critical_vuln',
    scanCompleted: 'scan_completed',
    slaOverdue: 'sla_overdue',
    newTarget: 'new_target',
} as const;

type NotifyFlags = {
    criticalVuln: boolean;
    scanCompleted: boolean;
    slaOverdue: boolean;
    newTarget: boolean;
};

function eventsArrayToFlags(arr: string[]): NotifyFlags {
    const set = new Set(arr);
    return {
        criticalVuln: set.has(NOTIFY_EVENTS.criticalVuln),
        scanCompleted: set.has(NOTIFY_EVENTS.scanCompleted),
        slaOverdue: set.has(NOTIFY_EVENTS.slaOverdue),
        newTarget: set.has(NOTIFY_EVENTS.newTarget),
    };
}

function flagsToEventsArray(flags: NotifyFlags): string[] {
    const arr: string[] = [];
    if (flags.criticalVuln) arr.push(NOTIFY_EVENTS.criticalVuln);
    if (flags.scanCompleted) arr.push(NOTIFY_EVENTS.scanCompleted);
    if (flags.slaOverdue) arr.push(NOTIFY_EVENTS.slaOverdue);
    if (flags.newTarget) arr.push(NOTIFY_EVENTS.newTarget);
    return arr;
}

export const settingsRouter = router({
    /** Profile — name / email / role / MFA status. Email + role are read-only. */
    getProfile: protectedProcedure.query(async ({ ctx }) => {
        const user = await ctx.prisma.user.findUnique({
            where: { id: ctx.user!.userId },
            select: { id: true, name: true, email: true, role: true, mfaEnabled: true, createdAt: true },
        });
        if (!user) throw new TRPCError({ code: 'NOT_FOUND', message: 'User record missing' });
        return user;
    }),

    /** Update display name. Email and role are intentionally not mutable here. */
    updateProfile: protectedProcedure
        .input(z.object({
            name: z.string().min(1, 'Name cannot be empty').max(80, 'Name too long'),
        }))
        .mutation(async ({ ctx, input }) => {
            const updated = await ctx.prisma.user.update({
                where: { id: ctx.user!.userId },
                data: { name: input.name.trim() },
                select: { id: true, name: true, email: true, role: true },
            });
            // Audit log — pattern mirrors auth.changePassword for consistency.
            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'profile_updated',
                    resource: 'user',
                    resourceId: ctx.user!.userId,
                    details: JSON.stringify({ fields: ['name'] }),
                },
            });
            return updated;
        }),

    /**
     * Read the user's notification prefs. We use a single "email" channel
     * NotificationConfig row per user — the `events` JSON array inside
     * encodes which events fire a notification. On first read (no row
     * exists) we auto-create one with all flags off so the UI always has
     * something sensible to display.
     */
    getNotificationPrefs: protectedProcedure.query(async ({ ctx }): Promise<NotifyFlags> => {
        let config = await ctx.prisma.notificationConfig.findFirst({
            where: { userId: ctx.user!.userId, channel: 'email' },
        });
        if (!config) {
            config = await ctx.prisma.notificationConfig.create({
                data: {
                    userId: ctx.user!.userId,
                    channel: 'email',
                    config: JSON.stringify({ email: '' }),
                    events: JSON.stringify([]),
                    isActive: true,
                },
            });
        }
        let events: string[] = [];
        try {
            const parsed = JSON.parse(config.events);
            if (Array.isArray(parsed)) events = parsed;
        } catch { /* malformed — treat as empty */ }
        return eventsArrayToFlags(events);
    }),

    /** Upsert notification prefs. Keeps the existing config (email address) intact. */
    updateNotificationPrefs: protectedProcedure
        .input(z.object({
            criticalVuln: z.boolean(),
            scanCompleted: z.boolean(),
            slaOverdue: z.boolean(),
            newTarget: z.boolean(),
        }))
        .mutation(async ({ ctx, input }) => {
            const existing = await ctx.prisma.notificationConfig.findFirst({
                where: { userId: ctx.user!.userId, channel: 'email' },
            });
            const eventsJson = JSON.stringify(flagsToEventsArray(input));
            if (existing) {
                await ctx.prisma.notificationConfig.update({
                    where: { id: existing.id },
                    data: { events: eventsJson },
                });
            } else {
                await ctx.prisma.notificationConfig.create({
                    data: {
                        userId: ctx.user!.userId,
                        channel: 'email',
                        config: JSON.stringify({ email: '' }),
                        events: eventsJson,
                        isActive: true,
                    },
                });
            }
            await ctx.prisma.auditLog.create({
                data: {
                    userId: ctx.user!.userId,
                    action: 'notification_prefs_updated',
                    resource: 'user',
                    resourceId: ctx.user!.userId,
                    details: eventsJson,
                },
            });
            return { ok: true };
        }),
});
