// Version du paquet, pour la `source` des documents produits (EX-7.19).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pkg = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "package.json"), "utf8"));

/** Version de `@noortrace/inscription`. */
export const VERSION = pkg.version;

/** Producteur : `@noortrace/inscription <version>`. */
export const SOURCE = `${pkg.name} ${pkg.version}`;
