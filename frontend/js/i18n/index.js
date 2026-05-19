import fr from "./fr.js";
import en from "./en.js";
import { state } from "../state.js";

const dictionaries = {
  fr,
  en,
};

export function t(key, params = {}) {
  const lang = state.language || "fr";
  const dict = dictionaries[lang] || dictionaries.fr;

  let value = dict[key] || dictionaries.fr[key] || key;

  for (const [name, paramValue] of Object.entries(params)) {
    value = value.replaceAll(`{${name}}`, String(paramValue));
  }

  return value;
}
