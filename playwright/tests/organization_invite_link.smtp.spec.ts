import { test, expect, type Page, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from '../global-utils';
import * as orgs from './setups/orgs';
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

let mailServer, mail1Buffer, mail2Buffer;
let inviteLink: string;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailServer = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailServer.listen();

    await utils.startVault(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
    });

    mail1Buffer = mailServer.buffer(users.user1.email);
    mail2Buffer = mailServer.buffer(users.user2.email);
});

test.afterAll('Teardown', async ({}, testInfo: TestInfo) => {
    utils.stopVault(testInfo);
    [mail1Buffer, mail2Buffer, mailServer].map((m) => m?.close());
});

// Joining through an invite link needs web vault 2026.8.1 or newer
test.beforeEach(async ({ request }) => {
    const { version } = await (await request.get('/version.json')).json();
    const [year, month, patch] = version.split('.').map(Number);
    test.skip(year * 10000 + month * 100 + patch < 20260801, `Web vault ${version} can't join through invite links`);
});

async function openInviteLinkTab(page: Page) {
    await page.getByRole('button', { name: 'Invite member' }).click();
    await page.getByRole('tab', { name: 'By link' }).click();
}

async function copyInviteLink(page: Page): Promise<string> {
    await page.locator('footer').getByRole('button', { name: 'Copy link' }).click();
    await utils.checkNotification(page, 'Invite link copied');
    return await page.evaluate(() => navigator.clipboard.readText());
}

test('Create invite link', async ({ page }) => {
    await createAccount(test, page, users.user1, mail1Buffer);
    await orgs.create(test, page, 'Test');
    await orgs.members(test, page, 'Test');

    await test.step('Create link', async () => {
        await openInviteLinkTab(page);
        await page.getByRole('textbox', { name: /Allowed domains/ }).fill('example.com');
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Domains edited');

        inviteLink = await copyInviteLink(page);
        expect(inviteLink).toMatch(/\/#\/join\/[0-9a-f-]{36}\/[0-9a-f-]{36}\?key=/);
    });
});

test('Join with a new account', async ({ page }) => {
    await utils.cleanLanding(page);

    await test.step('Register through the link', async () => {
        await page.goto(inviteLink);
        await expect(page.getByRole('heading', { name: 'Join Test' })).toBeVisible();
        await page.getByLabel(/Email address/).fill(users.user2.email);
        await page.getByLabel('Name').fill(users.user2.name);
        await page.getByRole('button', { name: 'Continue' }).click();
        await expect(page.getByRole('heading', { name: 'Check your email' })).toBeVisible();
    });

    await test.step('Finish the registration and join', async () => {
        const verify = await mail2Buffer.expect((m) => m.subject === 'Verify Your Email');
        await page.goto(verify.text.match(/https?:\/\/\S+sealedOpenOrgInviteData=\S+/)[0]);

        await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(users.user2.password);
        await page.getByRole('textbox', { name: 'Confirm master password * (' }).fill(users.user2.password);
        await page.getByRole('button', { name: 'Create account' }).click();
        await utils.checkNotification(page, 'Successfully accepted your invitation');
    });
});

test('Confirm the new member', async ({ page }) => {
    await logUser(test, page, users.user1);
    await orgs.members(test, page, 'Test');

    await expect(page.getByRole('row').filter({ hasText: users.user2.email })).toContainText('Needs confirmation');
    await orgs.confirm(test, page, 'Test', users.user2.email);
});

test('Regenerate and deactivate the link', async ({ page }) => {
    await logUser(test, page, users.user1);
    await orgs.members(test, page, 'Test');
    await openInviteLinkTab(page);

    await page.getByRole('button', { name: 'Regenerate invite link' }).click();
    await utils.checkNotification(page, 'Invite link regenerated');
    const newLink = await copyInviteLink(page);
    expect(newLink).not.toEqual(inviteLink);

    await page.getByRole('button', { name: 'Deactivate link' }).click();
    await utils.checkNotification(page, 'Invite link invalidated');

    await utils.cleanLanding(page);
    for (const link of [inviteLink, newLink]) {
        await page.goto(link);
        await expect(page.getByText('The invite link is no longer valid.')).toBeVisible();
    }
});
