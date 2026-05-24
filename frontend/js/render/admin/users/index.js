import { renderUserCard } from "./card.js";

export { renderUserCard } from "./card.js";
export { renderCreateUserBlock } from "./create-form.js";

export function renderUserCardList(users, emailAvailable = true) {
  return users.map((u) => renderUserCard(u, emailAvailable)).join("");
}
