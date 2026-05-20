import {
    CustomRequest,
    Env,
    UserPreferences,
    DEFAULT_PREFERENCES,
    THEME_VALUES,
    DENSITY_VALUES,
    SHAPE_VALUES,
    ACCENT_VALUES,
    ThemePref,
    DensityPref,
    ShapePref,
    AccentPref
} from './types.js';
import { jsonResponse } from './utils.js';
import { logAudit } from './auditLog.js';

function isOneOf<T extends string>(value: unknown, allowed: ReadonlyArray<T>): value is T {
    return typeof value === 'string' && (allowed as ReadonlyArray<string>).includes(value);
}

export async function handleGetPreferences(request: CustomRequest, env: Env, _ctx: ExecutionContext): Promise<Response> {
    if (!request.user) {
        return jsonResponse({ message: 'Unauthorized.' }, 401);
    }

    try {
        const row = await env.DB.prepare(
            'SELECT user_id, theme, density, shape, accent, updated_at FROM user_preferences WHERE user_id = ?'
        ).bind(request.user.userId).first<UserPreferences>();

        if (row) {
            return jsonResponse(row);
        }

        return jsonResponse({
            user_id: request.user.userId,
            ...DEFAULT_PREFERENCES,
            updated_at: null
        });
    } catch (error: any) {
        console.error('Get preferences error:', error);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}

export async function handleUpdatePreferences(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!request.user) {
        return jsonResponse({ message: 'Unauthorized.' }, 401);
    }

    let body: Partial<{ theme: unknown; density: unknown; shape: unknown; accent: unknown }>;
    try {
        body = await request.json() as typeof body;
    } catch {
        return jsonResponse({ message: 'Invalid JSON body.' }, 400);
    }

    if (body === null || typeof body !== 'object') {
        return jsonResponse({ message: 'Invalid request body.' }, 400);
    }

    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    const userId = request.user.userId;

    const existing = await env.DB.prepare(
        'SELECT theme, density, shape, accent FROM user_preferences WHERE user_id = ?'
    ).bind(userId).first<Pick<UserPreferences, 'theme' | 'density' | 'shape' | 'accent'>>();

    const base = existing ?? DEFAULT_PREFERENCES;

    const theme:   ThemePref   = body.theme   !== undefined ? (isOneOf(body.theme,   THEME_VALUES)   ? body.theme   : null as any) : base.theme;
    const density: DensityPref = body.density !== undefined ? (isOneOf(body.density, DENSITY_VALUES) ? body.density : null as any) : base.density;
    const shape:   ShapePref   = body.shape   !== undefined ? (isOneOf(body.shape,   SHAPE_VALUES)   ? body.shape   : null as any) : base.shape;
    const accent:  AccentPref  = body.accent  !== undefined ? (isOneOf(body.accent,  ACCENT_VALUES)  ? body.accent  : null as any) : base.accent;

    if (theme === null || density === null || shape === null || accent === null) {
        return jsonResponse({
            message: 'Invalid preference value.',
            allowed: { theme: THEME_VALUES, density: DENSITY_VALUES, shape: SHAPE_VALUES, accent: ACCENT_VALUES }
        }, 400);
    }

    try {
        await env.DB.prepare(
            `INSERT INTO user_preferences (user_id, theme, density, shape, accent, updated_at)
             VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(user_id) DO UPDATE SET
                theme = excluded.theme,
                density = excluded.density,
                shape = excluded.shape,
                accent = excluded.accent,
                updated_at = CURRENT_TIMESTAMP`
        ).bind(userId, theme, density, shape, accent).run();

        const saved = await env.DB.prepare(
            'SELECT user_id, theme, density, shape, accent, updated_at FROM user_preferences WHERE user_id = ?'
        ).bind(userId).first<UserPreferences>();

        logAudit(env, ctx, userId, 'PREFERENCES_UPDATE', { theme, density, shape, accent }, ipAddress, userAgent);
        return jsonResponse(saved!);
    } catch (error: any) {
        console.error('Update preferences error:', error);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}
