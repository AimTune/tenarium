import { dialog, expect, expectToast, field, go, signIn, test, unique } from "./fixtures";

test("creates and edits a plan and shows its revisions", async ({ page }) => {
  await signIn(page);
  await go(page, "Plans");
  // The seeded plans.
  await expect(page.getByRole("row", { name: /Free/ })).toBeVisible();
  await expect(page.getByRole("row", { name: /Pro/ })).toBeVisible();

  const id = unique("team");
  await page.getByRole("button", { name: "New plan" }).click();
  const dlg = dialog(page, "New plan");
  await field(dlg, "ID").fill(id);
  await field(dlg, "Name").fill(`Team ${id}`);
  await field(dlg, "Features (JSON)").fill('{"sso": true, "beta_reports": false}');
  await field(dlg, "Limits (JSON)").fill("{not json");
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(dlg.getByRole("alert")).toHaveText("Limits must be valid JSON");
  await field(dlg, "Limits (JSON)").fill('{"members": 25}');
  await dlg.getByRole("button", { name: "Create" }).click();
  await expect(dlg).toBeHidden();
  await expectToast(page, "Plan saved");

  const row = page.getByRole("row", { name: new RegExp(id) });
  await expect(row).toContainText("members=25");

  await row.getByRole("button", { name: "Edit" }).click();
  const edlg = dialog(page, `Edit plan ${id}`);
  await field(edlg, "Limits (JSON)").fill('{"members": 50}');
  await field(edlg, "Grandfather current tenants").check();
  await edlg.getByRole("button", { name: "Save" }).click();
  await expect(edlg).toBeHidden();
  await expect(row).toContainText("members=50");

  await row.getByRole("button", { name: "Revisions" }).click();
  const rdlg = dialog(page, `Revisions of Team ${id}`);
  await expect(rdlg).toBeVisible();
  await expect(rdlg.getByRole("columnheader", { name: "Revision" })).toBeVisible();
  await expect(rdlg.getByRole("row", { name: /members=25/ })).toBeVisible();
  await rdlg.getByRole("button", { name: "Close" }).click();
  await expect(rdlg).toBeHidden();

  await row.getByRole("button", { name: "Delete" }).click();
  await dialog(page, "Delete plan").getByRole("button", { name: "Delete" }).click();
  await expectToast(page, "Plan deleted");
  await expect(row).toBeHidden();
});

test("creates, toggles and deletes a feature rollout", async ({ page }) => {
  await signIn(page);
  await go(page, "Rollouts", "Feature rollouts");
  const feature = unique("beta_editor").replace(/-/g, "_");

  await page.getByRole("button", { name: "New rollout" }).click();
  const dlg = dialog(page, "New rollout");
  await field(dlg, "Feature").fill(feature);
  const slider = dlg.getByRole("slider");
  await expect(slider).toHaveValue("10");
  await slider.fill("40");
  await expect(dlg.locator("output")).toHaveText("40%");
  await dlg.getByRole("group", { name: "Plans" }).getByLabel("Pro", { exact: true }).check();
  await dlg.getByRole("group", { name: "Regions" }).getByLabel("eu", { exact: true }).check();
  await field(dlg, "Labels").fill("tier=beta");
  await dlg.getByRole("button", { name: "Save" }).click();
  await expect(dlg).toBeHidden();
  await expectToast(page, "Rollout saved");

  const row = page.getByRole("row", { name: new RegExp(feature) });
  await expect(row).toContainText("40%");
  await expect(row.getByRole("meter")).toHaveAttribute("aria-valuenow", "40");
  await expect(row).toContainText("tier=beta");
  await expect(row.getByRole("cell", { name: "on", exact: true })).toBeVisible();

  await row.getByRole("button", { name: "Turn off" }).click();
  await expectToast(page, "Rollout turned off");
  await expect(row.getByRole("button", { name: "Turn on" })).toBeVisible();
  await expect(row.getByRole("cell", { name: "off", exact: true })).toBeVisible();

  // Editing keeps the targeting and moves the slider.
  await row.getByRole("button", { name: "Edit" }).click();
  const edlg = dialog(page, `Edit rollout of ${feature}`);
  await expect(edlg.getByRole("slider")).toHaveValue("40");
  await expect(edlg.getByRole("group", { name: "Plans" }).getByLabel("Pro", { exact: true })).toBeChecked();
  await edlg.getByRole("slider").fill("75");
  await edlg.getByRole("button", { name: "Save" }).click();
  await expect(edlg).toBeHidden();
  await expect(row).toContainText("75%");

  await row.getByRole("button", { name: "Delete" }).click();
  await dialog(page, "Delete rollout").getByRole("button", { name: "Delete" }).click();
  await expectToast(page, "Rollout deleted");
  await expect(row).toBeHidden();
});
