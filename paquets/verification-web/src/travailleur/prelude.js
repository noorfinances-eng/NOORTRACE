"use strict";
// Prélude du travailleur de la page de vérification (CT-6 §18, EX-18.8).
//
// travailleur.js est fait de ce prélude, puis de wasm_exec.js de la chaîne Go
// sans changement, puis du pilote. Le prélude définit, avant wasm_exec.js,
// les trois objets que le paquet syscall de Go lit sous js/wasm et que
// wasm_exec.js ne définit que s'ils sont absents :
//   - globalThis.fs : un système de fichiers en lecture seule, l'arbre
//     /entrees/dossier/…, /entrees/ancres.json, /entrees/entetes-bitcoin.json,
//     de la forme à fonctions de rappel de l'API fs de Node ; les octets
//     écrits sur les descripteurs 1 et 2 sont recueillis ;
//   - globalThis.process : répertoire de travail /entrees, identité 0 ;
//   - globalThis.path : resolve, comme celui de Node.
// La directive "use strict" ci-dessus, en tête du fichier, vaut pour tout
// travailleur.js, wasm_exec.js compris (qui la porte lui-même en tête).
//
// Le pilote emploie l'objet NOORTRACE_ARBRE pour installer l'arbre d'une
// vérification et recueillir les sorties de chaque exécution.

const NOORTRACE_ARBRE = (() => {
  // Types et droits (EX-18.8) : répertoires S_IFDIR | 0555, fichiers S_IFREG | 0444.
  const S_IFDIR = 0o040000;
  const S_IFREG = 0o100000;
  const MODE_REPERTOIRE = S_IFDIR | 0o555;
  const MODE_FICHIER = S_IFREG | 0o444;
  // Constantes d'ouverture de Node sous Linux, lues par le paquet syscall à
  // son initialisation (EX-18.8).
  const constantes = Object.freeze({
    O_WRONLY: 1,
    O_RDWR: 2,
    O_CREAT: 64,
    O_EXCL: 128,
    O_TRUNC: 512,
    O_APPEND: 1024,
    O_DIRECTORY: 65536,
  });
  const ECRITURE = constantes.O_WRONLY | constantes.O_RDWR | constantes.O_CREAT
    | constantes.O_EXCL | constantes.O_TRUNC | constantes.O_APPEND;
  const REPERTOIRE_DE_TRAVAIL = "/entrees";
  const PERIPHERIQUE = 1;
  const PREMIER_DESCRIPTEUR = 3;

  let racine = null;
  let descripteurs = new Map();
  let prochainDescripteur = PREMIER_DESCRIPTEUR;
  let sorties = null;

  /** Erreur dont le membre `code` est le nom POSIX, que syscall traduit. */
  function erreur(code) {
    const e = new Error(code);
    e.code = code;
    return e;
  }

  function nouveauRepertoire(parent) {
    const n = { repertoire: true, parent: null, enfants: new Map(), ino: 0, octets: null };
    n.parent = parent ?? n;
    return n;
  }

  /** Ordre des noms : celui de leurs octets UTF-8 (ordre de Go). */
  function comparerNoms(a, b) {
    const ea = new TextEncoder().encode(a);
    const eb = new TextEncoder().encode(b);
    const n = Math.min(ea.length, eb.length);
    for (let i = 0; i < n; i++) {
      if (ea[i] !== eb[i]) return ea[i] - eb[i];
    }
    return ea.length - eb.length;
  }

  function composantValide(c) {
    return c !== "" && c !== "." && c !== ".." && !c.includes("/") && !c.includes("\0");
  }

  /**
   * Installe l'arbre d'une vérification. `fichiers` : [{ chemin, octets }],
   * `repertoires` : [chemin], chemins relatifs à /entrees. Lève une erreur si
   * un chemin est mal formé, en double, ou à la fois fichier et répertoire.
   */
  function installer(fichiers, repertoires) {
    const r = nouveauRepertoire(null);
    const entrees = nouveauRepertoire(r);
    r.enfants.set("entrees", entrees);
    const dossier = nouveauRepertoire(entrees);
    entrees.enfants.set("dossier", dossier);
    const descendre = (chemin, creerDernier) => {
      if (typeof chemin !== "string") throw new TypeError("chemin d'entrée qui n'est pas une chaîne");
      const parties = chemin.split("/");
      if (!parties.every(composantValide)) throw new TypeError(`chemin d'entrée mal formé : ${JSON.stringify(chemin)}`);
      let courant = entrees;
      for (let i = 0; i < parties.length - 1; i++) {
        let suivant = courant.enfants.get(parties[i]);
        if (suivant === undefined) {
          suivant = nouveauRepertoire(courant);
          courant.enfants.set(parties[i], suivant);
        } else if (!suivant.repertoire) {
          throw new TypeError(`chemin d'entrée à la fois fichier et répertoire : ${JSON.stringify(chemin)}`);
        }
        courant = suivant;
      }
      return creerDernier(courant, parties[parties.length - 1]);
    };
    for (const chemin of repertoires) {
      descendre(chemin, (parent, nom) => {
        const existant = parent.enfants.get(nom);
        if (existant !== undefined && !existant.repertoire) {
          throw new TypeError(`chemin d'entrée à la fois fichier et répertoire : ${JSON.stringify(chemin)}`);
        }
        if (existant === undefined) parent.enfants.set(nom, nouveauRepertoire(parent));
      });
    }
    for (const { chemin, octets } of fichiers) {
      if (Object.prototype.toString.call(octets) !== "[object Uint8Array]") throw new TypeError(`octets d'entrée absents : ${JSON.stringify(chemin)}`);
      descendre(chemin, (parent, nom) => {
        if (parent.enfants.has(nom)) throw new TypeError(`chemin d'entrée en double : ${JSON.stringify(chemin)}`);
        parent.enfants.set(nom, { repertoire: false, parent, enfants: null, ino: 0, octets });
      });
    }
    // Couples (dev, ino) stables : numérotation en profondeur, noms triés.
    let ino = 0;
    const numeroter = (n) => {
      n.ino = ++ino;
      if (!n.repertoire) return;
      const noms = [...n.enfants.keys()].sort(comparerNoms);
      const tries = new Map();
      for (const nom of noms) tries.set(nom, n.enfants.get(nom));
      n.enfants = tries;
      for (const enfant of tries.values()) numeroter(enfant);
    };
    numeroter(r);
    racine = r;
    descripteurs = new Map();
    prochainDescripteur = PREMIER_DESCRIPTEUR;
  }

  /** Retire l'arbre et les descripteurs. */
  function retirer() {
    racine = null;
    descripteurs = new Map();
    prochainDescripteur = PREMIER_DESCRIPTEUR;
  }

  /** Ouvre le recueil des sorties 1 et 2 d'une exécution. */
  function ouvrirSorties() {
    sorties = { 1: [], 2: [] };
    descripteurs = new Map();
    prochainDescripteur = PREMIER_DESCRIPTEUR;
  }

  function concatener(morceaux) {
    let n = 0;
    for (const m of morceaux) n += m.length;
    const tout = new Uint8Array(n);
    let i = 0;
    for (const m of morceaux) {
      tout.set(m, i);
      i += m.length;
    }
    return tout;
  }

  /** Ferme le recueil et rend { sortie, erreur } (Uint8Array). */
  function fermerSorties() {
    const s = sorties;
    sorties = null;
    if (s === null) return { sortie: new Uint8Array(0), erreur: new Uint8Array(0) };
    return { sortie: concatener(s[1]), erreur: concatener(s[2]) };
  }

  /**
   * Résolution d'un chemin comme le noyau : composant après composant, sans
   * lien ; un composant suivi d'une barre oblique doit être un répertoire.
   */
  function resoudre(chemin) {
    if (racine === null) return { erreur: "ENOENT" };
    if (typeof chemin !== "string" || chemin === "") return { erreur: "ENOENT" };
    let courant = chemin.startsWith("/") ? racine : resoudre(REPERTOIRE_DE_TRAVAIL).noeud;
    const parties = chemin.split("/");
    for (let i = 0; i < parties.length; i++) {
      const p = parties[i];
      if (p === "") {
        if (i > 0 && !courant.repertoire) return { erreur: "ENOTDIR" };
        continue;
      }
      if (!courant.repertoire) return { erreur: "ENOTDIR" };
      if (p === ".") continue;
      if (p === "..") {
        courant = courant.parent;
        continue;
      }
      const suivant = courant.enfants.get(p);
      if (suivant === undefined) return { erreur: "ENOENT" };
      courant = suivant;
    }
    return { noeud: courant };
  }

  /** Objet d'état : tous les membres numériques que lit syscall, et isDirectory(). */
  function etat(n) {
    const repertoire = n.repertoire;
    let liens = 1;
    let taille = 0;
    if (repertoire) {
      liens = 2;
      for (const e of n.enfants.values()) if (e.repertoire) liens++;
    } else {
      taille = n.octets.length;
    }
    return {
      dev: PERIPHERIQUE,
      ino: n.ino,
      mode: repertoire ? MODE_REPERTOIRE : MODE_FICHIER,
      nlink: liens,
      uid: 0,
      gid: 0,
      rdev: 0,
      size: taille,
      blksize: 4096,
      blocks: Math.ceil(taille / 512),
      atimeMs: 0,
      mtimeMs: 0,
      ctimeMs: 0,
      isDirectory() {
        return repertoire;
      },
    };
  }

  function copier(tampon, debut, longueur) {
    return Uint8Array.prototype.slice.call(tampon, debut, debut + longueur);
  }

  const refuseEcriture = (...args) => args[args.length - 1](erreur("EROFS"));
  const nonOffert = (...args) => args[args.length - 1](erreur("ENOSYS"));

  const fs = {
    constants: constantes,
    // Écriture synchrone de l'environnement d'exécution de Go (runtime.wasmWrite :
    // messages d'arrêt) : recueillie comme write.
    writeSync(fd, tampon) {
      if ((fd === 1 || fd === 2) && sorties !== null) {
        sorties[fd].push(copier(tampon, 0, tampon.length));
        return tampon.length;
      }
      throw erreur("EBADF");
    },
    write(fd, tampon, decalage, longueur, position, rappel) {
      if (fd === 1 || fd === 2) {
        if (sorties === null) return rappel(erreur("EBADF"));
        if (position !== null && position !== undefined) return rappel(erreur("ENOSYS"));
        sorties[fd].push(copier(tampon, decalage, longueur));
        return rappel(null, longueur);
      }
      // Descripteur inconnu, ou ouvert en lecture seule : EBADF, comme le noyau.
      return rappel(erreur("EBADF"));
    },
    open(chemin, drapeaux, mode, rappel) {
      if ((drapeaux & ECRITURE) !== 0) return rappel(erreur("EROFS"));
      const r = resoudre(chemin);
      if (r.erreur) return rappel(erreur(r.erreur));
      if ((drapeaux & constantes.O_DIRECTORY) !== 0 && !r.noeud.repertoire) return rappel(erreur("ENOTDIR"));
      const fd = prochainDescripteur++;
      descripteurs.set(fd, { noeud: r.noeud, position: 0 });
      return rappel(null, fd);
    },
    close(fd, rappel) {
      if (!descripteurs.delete(fd)) return rappel(erreur("EBADF"));
      return rappel(null);
    },
    fstat(fd, rappel) {
      const d = descripteurs.get(fd);
      if (d === undefined) return rappel(erreur("EBADF"));
      return rappel(null, etat(d.noeud));
    },
    stat(chemin, rappel) {
      const r = resoudre(chemin);
      if (r.erreur) return rappel(erreur(r.erreur));
      return rappel(null, etat(r.noeud));
    },
    lstat(chemin, rappel) {
      const r = resoudre(chemin);
      if (r.erreur) return rappel(erreur(r.erreur));
      return rappel(null, etat(r.noeud));
    },
    read(fd, tampon, decalage, longueur, position, rappel) {
      const d = descripteurs.get(fd);
      if (d === undefined) return rappel(erreur("EBADF"));
      if (d.noeud.repertoire) return rappel(erreur("EISDIR"));
      const octets = d.noeud.octets;
      const depuis = position === null || position === undefined ? d.position : position;
      const n = Math.max(0, Math.min(longueur, octets.length - depuis));
      if (n > 0) tampon.set(octets.subarray(depuis, depuis + n), decalage);
      if (position === null || position === undefined) d.position += n;
      return rappel(null, n);
    },
    readdir(chemin, rappel) {
      const r = resoudre(chemin);
      if (r.erreur) return rappel(erreur(r.erreur));
      if (!r.noeud.repertoire) return rappel(erreur("ENOTDIR"));
      return rappel(null, [...r.noeud.enfants.keys()]);
    },
    // Opérations d'écriture : refusées, EROFS.
    chmod: refuseEcriture,
    chown: refuseEcriture,
    fchmod: refuseEcriture,
    fchown: refuseEcriture,
    lchown: refuseEcriture,
    link: refuseEcriture,
    mkdir: refuseEcriture,
    rename: refuseEcriture,
    rmdir: refuseEcriture,
    symlink: refuseEcriture,
    truncate: refuseEcriture,
    ftruncate: refuseEcriture,
    unlink: refuseEcriture,
    utimes: refuseEcriture,
    // Autres opérations : non offertes, ENOSYS.
    fsync: nonOffert,
    readlink: nonOffert,
  };

  const processus = {
    cwd() {
      return REPERTOIRE_DE_TRAVAIL;
    },
    chdir() {
      throw erreur("ENOSYS");
    },
    pid: 1,
    ppid: 0,
    getuid() {
      return 0;
    },
    getgid() {
      return 0;
    },
    geteuid() {
      return 0;
    },
    getegid() {
      return 0;
    },
    getgroups() {
      return [];
    },
    umask() {
      return 0o022;
    },
  };

  /** Normalisation lexicale d'un chemin, comme path.posix de Node. */
  function normaliser(chemin) {
    const pile = [];
    for (const p of chemin.split("/")) {
      if (p === "" || p === ".") continue;
      if (p === "..") {
        pile.pop();
        continue;
      }
      pile.push(p);
    }
    return pile.join("/");
  }

  const chemins = {
    // Comme path.resolve de Node : de droite à gauche jusqu'au premier chemin
    // absolu, puis le répertoire de travail ; le résultat est normalisé.
    resolve(...segments) {
      let resolu = "";
      let absolu = false;
      for (let i = segments.length - 1; i >= -1 && !absolu; i--) {
        const s = i >= 0 ? segments[i] : processus.cwd();
        if (typeof s !== "string") throw new TypeError("path.resolve : segment qui n'est pas une chaîne");
        if (s.length === 0) continue;
        resolu = `${s}/${resolu}`;
        absolu = s.charCodeAt(0) === 47;
      }
      const n = normaliser(resolu);
      return absolu ? `/${n}` : (n.length > 0 ? n : ".");
    },
  };

  globalThis.fs = fs;
  globalThis.process = processus;
  globalThis.path = chemins;

  return Object.freeze({ installer, retirer, ouvrirSorties, fermerSorties });
})();
