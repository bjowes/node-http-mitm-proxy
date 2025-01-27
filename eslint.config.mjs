import pluginJs from "@eslint/js";
import globals from "globals";

export default [
  {
    files: ["**/*.{js,mjs,cjs,ts}"],
  },
  { languageOptions: { globals: globals.browser } },
  pluginJs.configs.recommended,
];