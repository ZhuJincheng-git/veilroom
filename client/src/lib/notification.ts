export const notificationDuration = 3_000;

export type NotificationKind = "success" | "warning" | "error";

export type AppNotification = {
  id: number;
  kind: NotificationKind;
  message: string;
};
