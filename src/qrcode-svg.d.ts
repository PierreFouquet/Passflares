// Minimal ambient declaration for `qrcode-svg` (ships no TypeScript types).
// We only use the in-memory `.svg()` renderer, never the file-writing API.
declare module 'qrcode-svg' {
    interface QRCodeOptions {
        content: string;
        padding?: number;
        width?: number;
        height?: number;
        color?: string;
        background?: string;
        ecl?: 'L' | 'M' | 'Q' | 'H';
        join?: boolean;
    }
    export default class QRCode {
        constructor(options: QRCodeOptions | string);
        svg(): string;
    }
}
