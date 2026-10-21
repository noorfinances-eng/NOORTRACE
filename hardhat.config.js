// Hardhat 3 ne cherche que hardhat.config.ts ou hardhat.config.js : ce fichier
// renvoie vers hardhat.config.mjs, la configuration de référence, pour que
// `npx hardhat compile`, `npx hardhat test` et `npx hardhat run` fonctionnent
// sans l'option --config.
export { default } from "./hardhat.config.mjs";
