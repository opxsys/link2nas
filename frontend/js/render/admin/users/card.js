import { html } from "../utils.js";
import { getUserCardFlags } from "./card/helpers.js";
import { renderUserSummary } from "./card/summary.js";
import { renderUserActions } from "./card/actions.js";
import { renderUserEditForms } from "./card/forms.js";

export function renderUserCard(u, emailAvailable = true) {
  const { isActive, isSuperAdmin, isEmailVerified, canUseLocalSpace } = getUserCardFlags(u);

  return `
    <article class="admin-user-card" data-user-id="${html(u.id)}">
      ${renderUserSummary(u, { isActive, isSuperAdmin, isEmailVerified, canUseLocalSpace })}

      ${renderUserActions(u, { isActive, isEmailVerified }, emailAvailable)}

      ${renderUserEditForms(u, { isActive, isSuperAdmin, isEmailVerified })}
    </article>
  `;
}
