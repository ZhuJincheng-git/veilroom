import { expect, test, type Page } from "@playwright/test";

function watchBrowserErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (error: Error) => errors.push(error.message));
  page.on("console", (message: { type: () => string; text: () => string }) => {
    if (message.type() === "error") errors.push(message.text());
  });
  return errors;
}

test.describe("VeilRoom anonymous session", () => {
  test("the creator enters the newly created session immediately", async ({ page }) => {
    const browserErrors = watchBrowserErrors(page);
    await page.goto("/");
    await page.waitForTimeout(1_300);
    await page.getByRole("button", { name: "创建私密会话" }).click();

    await expect(page).toHaveURL(/\/s\/[A-Za-z0-9_-]{20,}#p=[A-Za-z0-9_-]{20,}/);
    await expect(page.getByRole("heading", { name: "你的会话" })).toBeVisible();
    await expect(page.locator(".timer-block strong")).not.toHaveText("—:—");
    expect(browserErrors).toEqual([]);
  });

  test("a second participant locks the room and remains during the exit grace window", async ({ browser }) => {
    const creatorContext = await browser.newContext();
    const creator = await creatorContext.newPage();
    const creatorErrors = watchBrowserErrors(creator);
    await creator.goto("/");
    await creator.getByRole("button", { name: "创建私密会话" }).click();
    await expect(creator.getByRole("heading", { name: "你的会话" })).toBeVisible();
    const invitation = await creator.locator(".invite-drawer code").textContent();
    expect(invitation).toBeTruthy();

    const guestContext = await browser.newContext();
    const guest = await guestContext.newPage();
    const guestErrors = watchBrowserErrors(guest);
    await guest.goto(invitation!);
    await guest.getByRole("button", { name: "安全加入" }).click();
    await expect(guest.getByRole("heading", { name: "受邀会话" })).toBeVisible();

    await creator.getByRole("button", { name: "离开" }).click();
    await expect(guest.getByText("留存中")).toBeVisible();
    await expect(guest.getByRole("textbox", { name: "写下只属于此刻的话…" })).toBeDisabled();
    await expect(guest.locator(".timer-block strong")).toHaveText(/0:5[0-9]|1:00/);
    expect(creatorErrors).toEqual([]);
    expect(guestErrors).toEqual([]);

    await creatorContext.close();
    await guestContext.close();
  });
});
