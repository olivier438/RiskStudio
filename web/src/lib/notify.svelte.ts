/** Toasts (one at a time, like v4) and browser notifications. */

export type ToastKind = 'critical' | 'new' | 'info';

class Toasts {
	current = $state<{ message: string; kind: ToastKind } | null>(null);
	#timer: ReturnType<typeof setTimeout> | undefined;

	show(message: string, kind: ToastKind = 'info', durationMs = 6000): void {
		this.current = { message, kind };
		clearTimeout(this.#timer);
		this.#timer = setTimeout(() => this.dismiss(), durationMs);
	}

	dismiss(): void {
		this.current = null;
	}
}

export const toasts = new Toasts();

export function notificationsSupported(): boolean {
	return typeof window !== 'undefined' && 'Notification' in window;
}

/** Must be called from a user gesture (a click), as browsers require. */
export async function requestNotifications(): Promise<NotificationPermission | 'unsupported'> {
	if (!notificationsSupported()) return 'unsupported';
	if (Notification.permission === 'default') return Notification.requestPermission();
	return Notification.permission;
}

export function notify(title: string, body: string): void {
	if (notificationsSupported() && Notification.permission === 'granted') {
		new Notification(title, { body, icon: '/logo.jpg' });
	}
}
