// Parcours des familles de spec/vecteurs/ct-7 (annexe A.2 de CT-7) et
// confrontation de chaque valeur déclarée à la valeur recalculée.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Contexte porte ce que les familles partagent.
type Contexte struct {
	Racine    string
	Texte     *Texte
	Schemas   map[string]*Schema
	Comptes   map[string][]byte // chemin de dérivation → clé privée
	ParAdr    map[string][]byte // adresse → clé privée
	DP        []byte            // D_P de l'exemple, recalculé
	DCExemple []byte            // D_C de valide-creation-enregistreur
}

func lireJSON(rap *Rapport, chemin string) *Value {
	b, err := os.ReadFile(chemin)
	if err != nil {
		rap.Erreur("%v", err)
		return nil
	}
	v, err := AnalyserJSON(b)
	if err != nil {
		rap.Erreur("%s : %v", chemin, err)
		return nil
	}
	return v
}

func chaineOuNull(s string) string {
	if s == "" {
		return "null"
	}
	return s
}

func listeValeur(v *Value) string {
	if v.EstNull() {
		return "null"
	}
	var out []string
	for _, x := range v.Arr {
		if x.EstNull() {
			out = append(out, "null")
		} else {
			out = append(out, x.Chaine())
		}
	}
	return Liste(out)
}

// VerifierVecteurs parcourt la racine des vecteurs CT-7.
func VerifierVecteurs(racine string) *Rapport {
	rap := NouveauRapport(racine)
	ctx := &Contexte{Racine: racine, Schemas: map[string]*Schema{}}
	spec := filepath.Join(racine, "..", "..")
	t, err := LireTexte(filepath.Join(spec, "CT-7-securite-et-conformite.md"))
	if err != nil {
		rap.Erreur("texte de CT-7 introuvable : %v", err)
		return rap
	}
	ctx.Texte = t
	for _, nom := range []string{"ceremonie-cles-v0", "attestation-perimetre-v0", "matrice-conformite-v0", "modele-menace-v0"} {
		b, err := os.ReadFile(filepath.Join(spec, "schemas", nom+".schema.json"))
		if err != nil {
			rap.Erreur("schéma %s : %v", nom, err)
			return rap
		}
		s, err := ChargerSchema(nom, b)
		if err != nil {
			rap.Erreur("%v", err)
			return rap
		}
		ctx.Schemas[nom] = s
	}
	familleComptes(rap, ctx)
	familleCeremonies(rap, ctx)
	familleExempleCeremonie(rap, ctx)
	familleAttestations(rap, ctx)
	familleExempleAttestation(rap, ctx)
	familleCroises(rap, ctx)
	familleMatrice(rap, ctx)
	if m := lireJSON(rap, filepath.Join(racine, "menaces.json")); m != nil {
		VerifierMenaces(rap, m, ctx.Schemas["modele-menace-v0"], t)
		exempleMenaces(rap, ctx, m)
	}
	VerifierClesDeTest(rap, racine, ctx.Comptes)
	for _, f := range []string{"acceptation-securite-attendu.json", "acceptation-attestation-attendu.json", "acceptation-conformite-attendu.json"} {
		rap.HorsPerimetre("epreuves", f, "grille de l'épreuve à l'aveugle", "réponses d'un relecteur", "épreuve humaine (section 9) : aucune valeur à recalculer")
	}
	return rap
}

// familleComptes dérive les comptes du mnémonique de ct-3 et confronte
// attestations/constantes.json.
func familleComptes(rap *Rapport, ctx *Contexte) {
	const fam = "constantes"
	ctx.Comptes, ctx.ParAdr = map[string][]byte{}, map[string][]byte{}
	c3 := lireJSON(rap, filepath.Join(ctx.Racine, "..", "ct-3", "constantes.json"))
	c7 := lireJSON(rap, filepath.Join(ctx.Racine, "attestations", "constantes.json"))
	if c3 == nil || c7 == nil {
		return
	}
	mn := c3.Get("mnemonic").Chaine()
	rap.Comparer(fam, "attestations/constantes.json", "mnémonique (celui de ct-3/constantes.json, EX-A.1)", c7.Get("mnemonic").Chaine(), mn)
	cles, err := Comptes(mn, 10)
	if err != nil {
		rap.Erreur("dérivation des comptes : %v", err)
		return
	}
	for i, k := range cles {
		ch := fmt.Sprintf("m/44'/60'/0'/0/%d", i)
		ctx.Comptes[ch] = k
		a, _ := AdresseDePrivee(k)
		ctx.ParAdr[Hex0x(a)] = k
	}
	for _, a := range c7.Get("accounts").Arr {
		ch := a.Get("derivation_path").Chaine()
		k, ok := ctx.Comptes[ch]
		if !ok {
			rap.Erreur("compte %s non dérivé", ch)
			continue
		}
		adr, _ := AdresseDePrivee(k)
		rap.Comparer(fam, "compte "+ch, "adresse (BIP-39, BIP-32)", a.Get("address").Chaine(), Hex0x(adr))
	}
	rap.Comparer(fam, "attestations/constantes.json", "prefix_hex = P_P", c7.Get("prefix_hex").Chaine(), strings.TrimPrefix(Hex0x([]byte(PrefixeAttestation)), "0x"))
	rap.Comparer(fam, "attestations/constantes.json", "prefix_utf8 = P_P", c7.Get("prefix_utf8").Chaine(), PrefixeAttestation)
	rap.Comparer(fam, "attestations/constantes.json", "org_id = keccak256(slug)", c7.Chemin("org", "org_id").Chaine(), Hex0x(Keccak256([]byte(c7.Chemin("org", "slug").Chaine()))))
	for _, j := range c7.Get("journals").Arr {
		rap.Comparer(fam, "journal "+j.Get("name").Chaine(), "journal_id = keccak256(nom)", j.Get("journal_id").Chaine(), Hex0x(Keccak256([]byte(j.Get("name").Chaine()))))
	}
	label := c7.Chemin("rules_sha256", "label").Chaine()
	rap.Comparer(fam, "attestations/constantes.json", "rules_sha256 = SHA-256(étiquette)", c7.Chemin("rules_sha256", "sha256").Chaine(), Hex0x(SHA256([]byte(label))))
	s71, err := ctx.Texte.Section("### 7.1")
	if err == nil {
		joint := strings.Join(s71, " ")
		rap.Constater(fam, "texte de CT-7 §7.1", "étiquette de rules_sha256 citée par le texte", strings.Contains(strings.ReplaceAll(joint, "`", ""), label), label)
	}
	jeu := lireJSON(rap, filepath.Join(ctx.Racine, "attestations", "exemple", "jeu.json"))
	if jeu != nil {
		rap.Constater(fam, "attestations/constantes.json", "approver_set = exemple/jeu.json", Egales(jeu, c7.Get("approver_set")), "différents")
	}
}

var reCR = regexp.MustCompile(`CR-[0-9]+`)
var reAT = regexp.MustCompile(`AT-[0-9]+`)

// familleCeremonies rejoue chaque cas de ceremonies/ (EX-A.6).
func familleCeremonies(rap *Rapport, ctx *Contexte) {
	const fam = "ceremonies"
	sch := ctx.Schemas["ceremonie-cles-v0"]
	defAttendu, _ := sch.Sous("#/$defs/attendu")
	dir := filepath.Join(ctx.Racine, "ceremonies")
	entrees, err := os.ReadDir(dir)
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	cas := map[string]*Value{}
	for _, e := range entrees {
		if !e.IsDir() {
			continue
		}
		nom := e.Name()
		octets, err := os.ReadFile(filepath.Join(dir, nom, "proces-verbal.json"))
		if err != nil {
			rap.Erreur("%v", err)
			continue
		}
		att := lireJSON(rap, filepath.Join(dir, nom, "attendu.json"))
		if att == nil {
			continue
		}
		cas[nom] = att
		rap.Comparer(fam, nom, "attendu.json conforme à #/$defs/attendu", "[]", Liste(sch.ValiderContre(defAttendu, att)))
		r := VerifierCeremonie(octets, sch)
		verdict := "invalide"
		if r.Valide() {
			verdict = "valide"
		}
		rap.Comparer(fam, nom, "verdict", att.Get("verdict").Chaine(), verdict)
		rap.Comparer(fam, nom, "D_C", chaineOuNull(att.Get("digest").Chaine()), chaineOuNull(r.Digest))
		rap.Comparer(fam, nom, "vérifications en échec", listeValeur(att.Get("failed")), Liste(r.Echecs()))
		rap.Comparer(fam, nom, "vérifications non exécutées", listeValeur(att.Get("not_executed")), Liste(r.NonExecutees()))
		rap.Comparer(fam, nom, "signataires", listeValeur(att.Get("signers")), Liste(r.Signataires))
		if nom == "valide-creation-enregistreur" && r.Digest != "" {
			ctx.DCExemple, _ = OctetsHex(r.Digest, 32)
		}
		// Signatures reproduites (RFC 6979) pour les participants qui sont
		// des comptes de test et dont la signature est valide.
		if r.Digest == "" {
			continue
		}
		pv, _ := AnalyserJSON(octets)
		dc, _ := OctetsHex(r.Digest, 32)
		adresses := map[string]string{}
		for _, p := range pv.Get("participants").Arr {
			adresses[p.Get("id").Chaine()] = p.Get("address").Chaine()
		}
		for _, s := range pv.Get("signatures").Arr {
			a := adresses[s.Get("participant").Chaine()]
			rec, err := RecouvrerAdresse(MessageEIP191(dc), s.Get("signature").Chaine())
			k, ok := ctx.ParAdr[a]
			if err != nil || rec != a || !ok {
				continue
			}
			sig, _ := Signer(k, MessageEIP191(dc))
			rap.Comparer(fam, nom, "signature de "+s.Get("participant").Chaine()+" reproduite (RFC 6979)", s.Get("signature").Chaine(), sig)
		}
	}
	// Table d'A.4 : cas publiés au moins, et vérifications annoncées.
	sA4, err := ctx.Texte.Section("### A.4")
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	tb, err := TableEntete(sA4, "Cas", "Mutation")
	if err != nil {
		rap.Erreur("A.4 : %v", err)
		return
	}
	for _, l := range tb.Lignes {
		nom := SansCode(l[0])
		att, ok := cas[nom]
		rap.Constater(fam, nom, "cas exigé par la table d'A.4 publié", ok, "répertoire absent")
		if !ok {
			continue
		}
		annonce := reCR.FindAllString(strings.SplitN(l[2], "(", 2)[0], -1)
		if Liste(annonce) != listeValeur(att.Get("failed")) {
			rap.Note("ceremonies/%s : la table d'A.4 annonce %s en échec, attendu.json et le recalcul donnent %s (EX-A.6 : « seule la vérification visée échoue »)", nom, Liste(annonce), listeValeur(att.Get("failed")))
		}
	}
}

// familleExempleCeremonie confronte l'exemple calculé de 5.10 et le
// préfixe de 5.7 au cas valide-creation-enregistreur.
func familleExempleCeremonie(rap *Rapport, ctx *Contexte) {
	const fam = "exemple 5.10"
	s57, err1 := ctx.Texte.Section("### 5.7")
	s510, err2 := ctx.Texte.Section("### 5.10")
	if err1 != nil || err2 != nil {
		rap.Erreur("sections 5.7 ou 5.10 introuvables")
		return
	}
	bloc57, _ := BlocApres(s57, "EX-5.7")
	m := regexp.MustCompile(`= ([0-9a-f]+)\s+\(([0-9]+) octets\)`).FindStringSubmatch(bloc57)
	if m == nil {
		rap.Erreur("5.7 : valeur de P_C introuvable")
	} else {
		rap.Comparer(fam, "texte de CT-7 §5.7", "P_C en hexadécimal", m[1], strings.TrimPrefix(Hex0x([]byte(PrefixeCeremonie)), "0x"))
		rap.Comparer(fam, "texte de CT-7 §5.7", "longueur de P_C", m[2], fmt.Sprint(len(PrefixeCeremonie)))
	}
	jsonTexte, err := BlocApres(s510, "<!-- schema: ceremonie-cles -->")
	if err != nil {
		rap.Erreur("5.10 : %v", err)
		return
	}
	pvTexte, err := AnalyserJSONStrict([]byte(jsonTexte))
	if err != nil {
		rap.Erreur("5.10 : %v", err)
		return
	}
	rap.Comparer(fam, "texte de CT-7 §5.10", "conformité à ceremonie-cles-v0", "[]", Liste(ctx.Schemas["ceremonie-cles-v0"].Valider(pvTexte)))
	pvFichier := lireJSON(rap, filepath.Join(ctx.Racine, "ceremonies", "valide-creation-enregistreur", "proces-verbal.json"))
	if pvFichier != nil {
		rap.Constater(fam, "ceremonies/valide-creation-enregistreur", "procès-verbal = exemple de 5.10", Egales(pvTexte, pvFichier), "différents")
	}
	jcs, _ := Canonique(pvTexte.Sans("signatures"))
	for i, l := range s510 {
		if strings.HasPrefix(l, "Forme canonique `JCS(V)`") {
			if mm := regexp.MustCompile(`\(([0-9]+) octets`).FindStringSubmatch(l); mm != nil {
				rap.Comparer(fam, "texte de CT-7 §5.10", "longueur de JCS(V)", mm[1], fmt.Sprint(len(jcs)))
			}
			bloc, _ := BlocApres(s510[i:], "Forme canonique")
			rap.Comparer(fam, "texte de CT-7 §5.10", "JCS(V)", strings.TrimSuffix(bloc, "\n"), string(jcs))
		}
	}
	dc, _ := CondenseCeremonie(pvTexte)
	mEip := MessageEIP191(dc)
	cles := pvTexte.Get("keys").Arr
	pubEd, _ := OctetsHex(cles[0].Get("public_key").Chaine(), 32)
	pubCh, _ := OctetsHex(cles[1].Get("public_key").Chaine(), 65)
	adrCh, _ := AdresseDeCleNonCompressee(pubCh)
	sigs := map[string]string{}
	for _, s := range pvTexte.Get("signatures").Arr {
		sigs[s.Get("participant").Chaine()] = s.Get("signature").Chaine()
	}
	tb, err := TableEntete(s510, "Calcul", "Valeur")
	if err != nil {
		rap.Erreur("5.10 : %v", err)
		return
	}
	for _, l := range tb.Lignes {
		v := SansCode(l[1])
		switch {
		case strings.Contains(l[0], "Ed25519"):
			rap.Comparer(fam, "texte de CT-7 §5.10", l[0], v, Hex0x(SHA256(pubEd)))
		case strings.Contains(l[0], "clé publique de chaîne"):
			rap.Comparer(fam, "texte de CT-7 §5.10", l[0], v, Hex0x(SHA256(pubCh)))
		case strings.HasPrefix(l[0], "Adresse de chaîne"):
			rap.Comparer(fam, "texte de CT-7 §5.10", l[0], v, adrCh)
		case strings.HasPrefix(l[0], "`D_C"):
			rap.Comparer(fam, "texte de CT-7 §5.10", "D_C", v, Hex0x(dc))
		case strings.HasPrefix(l[0], "`M "):
			rap.Comparer(fam, "texte de CT-7 §5.10", "M", v, Hex0x(mEip))
		case strings.HasPrefix(l[0], "Signature de"):
			p := regexp.MustCompile("`(p[0-9]+)`").FindStringSubmatch(l[0])
			a := regexp.MustCompile(`0x[0-9a-f]{40}`).FindString(l[0])
			if p == nil {
				rap.Erreur("5.10 : ligne %q", l[0])
				continue
			}
			rap.Comparer(fam, "texte de CT-7 §5.10", "signature de "+p[1]+" (table = procès-verbal)", v, sigs[p[1]])
			rec, err := RecouvrerAdresse(mEip, v)
			rap.Comparer(fam, "texte de CT-7 §5.10", "adresse recouvrée de la signature de "+p[1], a, rec+texteErreur(err))
			if k, ok := ctx.ParAdr[a]; ok {
				sig, _ := Signer(k, mEip)
				rap.Comparer(fam, "texte de CT-7 §5.10", "signature de "+p[1]+" reproduite (RFC 6979)", v, sig)
			}
		default:
			rap.Erreur("5.10 : ligne de calcul non reconnue %q", l[0])
		}
	}
	attTexte, err := BlocApres(s510, "<!-- schema: ceremonie-cles/attendu -->")
	if err == nil {
		at, err := AnalyserJSON([]byte(attTexte))
		attF := lireJSON(rap, filepath.Join(ctx.Racine, "ceremonies", "valide-creation-enregistreur", "attendu.json"))
		if err == nil && attF != nil {
			rap.Constater(fam, "ceremonies/valide-creation-enregistreur", "attendu.json = attendu imprimé en 5.10", Egales(at, attF), "différents")
		}
	}
}

// statutsAttendus rend les statuts « AT-n statut raison » d'un attendu.
func statutsAttendus(v *Value) []string {
	var out []string
	for _, c := range v.Arr {
		r := c.Get("reason")
		raison := "null"
		if !r.EstNull() {
			raison = r.Chaine()
		}
		out = append(out, c.Get("id").Chaine()+" "+c.Get("status").Chaine()+" "+raison)
	}
	return out
}

func statutsObtenus(r *ResultatAttestation) []string {
	var out []string
	for _, s := range r.Statuts {
		out = append(out, s.ID+" "+s.Statut+" "+chaineOuNull(s.Raison))
	}
	return out
}

func recouvresTexte(r *ResultatAttestation) string {
	if r.Recouvres == nil {
		return "null"
	}
	var out []string
	for _, x := range r.Recouvres {
		if x == nil {
			out = append(out, "null")
		} else {
			out = append(out, *x)
		}
	}
	return Liste(out)
}

// familleAttestations rejoue attestations.json (EX-A.8).
func familleAttestations(rap *Rapport, ctx *Contexte) {
	const fam = "attestations"
	sch := ctx.Schemas["attestation-perimetre-v0"]
	f := lireJSON(rap, filepath.Join(ctx.Racine, "attestations", "attestations.json"))
	if f == nil {
		return
	}
	defF, _ := sch.Sous("#/$defs/fichier_vecteurs")
	rap.Comparer(fam, "attestations.json", "conformité à #/$defs/fichier_vecteurs", "[]", Liste(sch.ValiderContre(defF, f)))
	rap.Comparer(fam, "attestations.json", "prefix_hex = P_P", f.Get("prefix_hex").Chaine(), strings.TrimPrefix(Hex0x([]byte(PrefixeAttestation)), "0x"))
	parNom := map[string]*ResultatAttestation{}
	for _, c := range f.Get("cases").Arr {
		nom := c.Get("name").Chaine()
		e := c.Get("expected")
		r := VerifierAttestation(c.Chemin("input", "signed"), c.Chemin("input", "approver_set"), sch)
		parNom[nom] = r
		rap.Comparer(fam, nom, "digest (D_P recalculé)", chaineOuNull(e.Get("digest").Chaine()), chaineOuNull(r.Digest))
		rap.Comparer(fam, nom, "adresses recouvrées", listeValeur(e.Get("recovered")), recouvresTexte(r))
		rap.Comparer(fam, nom, "statuts de AT-1 à AT-4", Liste(statutsAttendus(e.Get("checks"))), Liste(statutsObtenus(r)))
		rap.Comparer(fam, nom, "retenue", fmt.Sprint(e.Get("retained").Bool), fmt.Sprint(r.Retenue))
		reproduireSignaturesAttestation(rap, ctx, fam, nom, c.Chemin("input", "signed"), r)
	}
	sA6, err := ctx.Texte.Section("### A.6")
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	tb, err := TableEntete(sA6, "Cas", "Altération")
	if err != nil {
		rap.Erreur("A.6 : %v", err)
		return
	}
	for _, l := range tb.Lignes {
		nom := SansCode(l[0])
		r, ok := parNom[nom]
		rap.Constater(fam, nom, "cas exigé par la table d'A.6 publié", ok, "cas absent")
		if !ok {
			continue
		}
		var echecs []string
		for _, s := range r.Statuts {
			if s.Statut == Echoue {
				echecs = append(echecs, s.ID)
			}
		}
		if annonce := reAT.FindAllString(l[2], -1); Liste(annonce) != Liste(echecs) {
			rap.Note("attestations/%s : la table d'A.6 annonce %s en échec, le recalcul donne %s", nom, Liste(annonce), Liste(echecs))
		}
	}
}

// reproduireSignaturesAttestation compare chaque signature valide d'un
// compte de test à sa reproduction déterministe (RFC 6979, 7.2).
func reproduireSignaturesAttestation(rap *Rapport, ctx *Contexte, fam, nom string, signee *Value, r *ResultatAttestation) {
	if r.Digest == "" || signee.Kind != KindObject {
		return
	}
	dp, _ := OctetsHex(r.Digest, 32)
	m := MessageEIP191(dp)
	for i, s := range signee.Get("signatures").Arr {
		if i >= len(r.Recouvres) || r.Recouvres[i] == nil {
			continue
		}
		k, ok := ctx.ParAdr[*r.Recouvres[i]]
		if !ok {
			continue
		}
		sig, _ := Signer(k, m)
		rap.Comparer(fam, nom, fmt.Sprintf("signatures[%d] reproduite (RFC 6979)", i), s.Get("signature").Chaine(), sig)
	}
}

// familleExempleAttestation confronte exemple/ et les valeurs de 7.1 à 7.5.
func familleExempleAttestation(rap *Rapport, ctx *Contexte) {
	const fam = "exemple 7.1-7.5"
	sch := ctx.Schemas["attestation-perimetre-v0"]
	dir := filepath.Join(ctx.Racine, "attestations", "exemple")
	p := lireJSON(rap, filepath.Join(dir, "attestation.json"))
	signee := lireJSON(rap, filepath.Join(dir, "attestation-signee.json"))
	cond := lireJSON(rap, filepath.Join(dir, "condense.json"))
	jeu := lireJSON(rap, filepath.Join(dir, "jeu.json"))
	jcsTxt, err := os.ReadFile(filepath.Join(dir, "jcs.txt"))
	if p == nil || signee == nil || cond == nil || jeu == nil || err != nil {
		rap.Erreur("exemple/ incomplet : %v", err)
		return
	}
	rap.Comparer(fam, "exemple/attestation.json", "conformité à attestation-perimetre-v0", "[]", Liste(sch.Valider(p)))
	jcs, err := Canonique(p)
	if err != nil {
		rap.Erreur("JCS(P) : %v", err)
		return
	}
	dp, _ := CondenseAttestation(p)
	ctx.DP = dp
	m := MessageEIP191(dp)
	rap.Comparer(fam, "exemple/jcs.txt", "JCS(P)", string(jcsTxt), string(jcs))
	n, _ := cond.Get("jcs_length").Entier()
	rap.Comparer(fam, "exemple/condense.json", "jcs_length", fmt.Sprint(n), fmt.Sprint(len(jcs)))
	rap.Comparer(fam, "exemple/condense.json", "digest = D_P", cond.Get("digest").Chaine(), Hex0x(dp))
	rap.Comparer(fam, "exemple/condense.json", "message = M", cond.Get("message").Chaine(), Hex0x(m))
	for i, s := range cond.Get("signatures").Arr {
		rec, err := RecouvrerAdresse(m, s.Get("signature").Chaine())
		rap.Comparer(fam, "exemple/condense.json", fmt.Sprintf("signatures[%d] : adresse recouvrée", i), s.Get("address").Chaine(), rec+texteErreur(err))
		if k, ok := ctx.ParAdr[s.Get("address").Chaine()]; ok {
			sig, _ := Signer(k, m)
			rap.Comparer(fam, "exemple/condense.json", fmt.Sprintf("signatures[%d] reproduite (RFC 6979)", i), s.Get("signature").Chaine(), sig)
		}
	}
	rap.Constater(fam, "exemple/attestation-signee.json", "attestation = exemple/attestation.json", Egales(signee.Get("attestation"), p), "différentes")
	rap.Constater(fam, "exemple/attestation-signee.json", "signatures = condense.json", Egales(signee.Get("signatures"), cond.Get("signatures")), "différentes")
	r := VerifierAttestation(signee, jeu, sch)
	rap.Comparer(fam, "exemple/attestation-signee.json", "AT-1 à AT-4 contre jeu.json", Liste([]string{"AT-1 reussi null", "AT-2 reussi null", "AT-3 reussi null", "AT-4 reussi null"}), Liste(statutsObtenus(r)))

	// Texte de 7.1 : l'exemple imprimé.
	s71, _ := ctx.Texte.Section("### 7.1")
	if bloc, err := BlocApres(s71, "<!-- schema: attestation-perimetre -->"); err == nil {
		pt, err := AnalyserJSONStrict([]byte(bloc))
		rap.Constater(fam, "texte de CT-7 §7.1", "exemple imprimé = exemple/attestation.json", err == nil && Egales(pt, p), texteErreur(err))
	} else {
		rap.Erreur("7.1 : %v", err)
	}
	// Texte de 7.2 : P_P et valeurs de l'exemple numérique.
	s72, _ := ctx.Texte.Section("### 7.2")
	if bloc, err := BlocApres(append([]string{"début de 7.2"}, s72...), "début de 7.2"); err == nil {
		if mm := regexp.MustCompile(`= ([0-9a-f]+)\s+\(([0-9]+) octets\)`).FindStringSubmatch(bloc); mm != nil {
			rap.Comparer(fam, "texte de CT-7 §7.2", "P_P en hexadécimal", mm[1], strings.TrimPrefix(Hex0x([]byte(PrefixeAttestation)), "0x"))
			rap.Comparer(fam, "texte de CT-7 §7.2", "longueur de P_P", mm[2], fmt.Sprint(len(PrefixeAttestation)))
		} else {
			rap.Erreur("7.2 : P_P introuvable")
		}
	}
	if bloc, err := BlocApres(s72, "Exemple numérique"); err == nil {
		if mm := regexp.MustCompile(`JCS\(P\)\s+= ([0-9]+) octets`).FindStringSubmatch(bloc); mm != nil {
			rap.Comparer(fam, "texte de CT-7 §7.2", "longueur de JCS(P)", mm[1], fmt.Sprint(len(jcs)))
		}
		if mm := regexp.MustCompile(`D_P\s+= (0x[0-9a-f]{64})`).FindStringSubmatch(bloc); mm != nil {
			rap.Comparer(fam, "texte de CT-7 §7.2", "D_P", mm[1], Hex0x(dp))
		}
		if mm := regexp.MustCompile(`\nM\s+= (0x[0-9a-f]{64})`).FindStringSubmatch(bloc); mm != nil {
			rap.Comparer(fam, "texte de CT-7 §7.2", "M", mm[1], Hex0x(m))
		}
		for _, mm := range regexp.MustCompile(`sig \((0x[0-9a-f]{40})\)\s+= (0x[0-9a-f]{130})`).FindAllStringSubmatch(bloc, -1) {
			rec, err := RecouvrerAdresse(m, mm[2])
			rap.Comparer(fam, "texte de CT-7 §7.2", "adresse recouvrée de la signature de "+mm[1], mm[1], rec+texteErreur(err))
			if k, ok := ctx.ParAdr[mm[1]]; ok {
				sig, _ := Signer(k, m)
				rap.Comparer(fam, "texte de CT-7 §7.2", "signature de "+mm[1]+" reproduite (RFC 6979)", mm[2], sig)
			}
		}
	} else {
		rap.Erreur("7.2 : %v", err)
	}
	joint := strings.Join(s72, " ")
	if mm := regexp.MustCompile("signature du compte 3 sur le même `M`, `(0x[0-9a-f]{130})`, attribuée au compte 2, recouvre `(0x[0-9a-f]{40})`").FindStringSubmatch(joint); mm != nil {
		rec, err := RecouvrerAdresse(m, mm[1])
		rap.Comparer(fam, "texte de CT-7 §7.2", "adresse recouvrée de la signature du compte 3", mm[2], rec+texteErreur(err))
		if k, ok := ctx.Comptes["m/44'/60'/0'/0/3"]; ok {
			sig, _ := Signer(k, m)
			rap.Comparer(fam, "texte de CT-7 §7.2", "signature du compte 3 reproduite (RFC 6979)", mm[1], sig)
		}
	} else {
		rap.Erreur("7.2 : phrase de la signature du compte 3 introuvable")
	}
	// Texte de 7.3 : le digest de la forme remise.
	s73, _ := ctx.Texte.Section("### 7.3")
	if bloc, err := BlocApres(s73, "Forme de l'attestation signée"); err == nil {
		if mm := regexp.MustCompile(`"digest": "(0x[0-9a-f]{64})"`).FindStringSubmatch(bloc); mm != nil {
			rap.Comparer(fam, "texte de CT-7 §7.3", "digest de l'attestation signée", mm[1], Hex0x(dp))
		}
	}
	// Texte de 7.5 : document de politique, son SHA-256 et son base64.
	s75, _ := ctx.Texte.Section("### 7.5")
	if bloc, err := BlocApres(s75, "Le document de"); err == nil {
		doc := regexp.MustCompile(`document = (\{.*\})`).FindStringSubmatch(bloc)
		sha := regexp.MustCompile(`SHA-256\s+= (0x[0-9a-f]{64})`).FindStringSubmatch(bloc)
		b64 := regexp.MustCompile(`base64\s+= ([A-Za-z0-9+/=]+)`).FindStringSubmatch(bloc)
		if doc == nil || sha == nil || b64 == nil {
			rap.Erreur("7.5 : document, SHA-256 ou base64 introuvable")
		} else {
			rap.Comparer(fam, "texte de CT-7 §7.5", "SHA-256 du document de politique", sha[1], Hex0x(SHA256([]byte(doc[1]))))
			rap.Comparer(fam, "texte de CT-7 §7.5", "base64 du document", b64[1], base64Standard([]byte(doc[1])))
			dv, err := AnalyserJSON([]byte(doc[1]))
			if err == nil {
				rap.Comparer(fam, "texte de CT-7 §7.5", "perimeter.attestation_digest = D_P", dv.Chemin("perimeter", "attestation_digest").Chaine(), Hex0x(dp))
				jcsDoc, _ := Canonique(dv)
				rap.Comparer(fam, "texte de CT-7 §7.5", "document en forme canonique (CT-2 EX-8.11)", doc[1], string(jcsDoc))
			}
			if evB, err := BlocApres(s75, "<!-- schema: evenement -->"); err == nil {
				ev, err := AnalyserJSON([]byte(evB))
				if err == nil {
					val := ev.Chemin("execution", "arguments", "value")
					rap.Comparer(fam, "texte de CT-7 §7.5", "événement : policy_sha256", val.Get("policy_sha256").Chaine(), sha[1])
					rap.Comparer(fam, "texte de CT-7 §7.5", "événement : policy_version = code.policy_version", val.Get("policy_version").Chaine(), ev.Chemin("code", "policy_version").Chaine())
					rap.Comparer(fam, "texte de CT-7 §7.5", "événement : execution.tool", "noortrace.journal.politique", ev.Chemin("execution", "tool").Chaine())
					rap.HorsPerimetre(fam, "texte de CT-7 §7.5", "hash et sig de l'événement", ev.Get("hash").Chaine(), "hachage et signature d'événement de CT-1 §6.1 et §6.2 : vérifiés par le vérificateur de ct-1 sur le dossier valide-seq-12-attestation-inscrite")
				}
			}
		}
	} else {
		rap.Erreur("7.5 : %v", err)
	}
}

// familleCroises rejoue croises.json (EX-A.9, EX-7.7).
func familleCroises(rap *Rapport, ctx *Contexte) {
	const fam = "croises"
	f := lireJSON(rap, filepath.Join(ctx.Racine, "attestations", "croises.json"))
	if f == nil || ctx.DP == nil {
		return
	}
	compte := f.Get("address").Chaine()
	if k, ok := ctx.Comptes["m/44'/60'/0'/0/1"]; ok {
		a, _ := AdresseDePrivee(k)
		rap.Comparer(fam, "croises.json", "adresse du compte 1", compte, Hex0x(a))
	}
	rap.Comparer(fam, "croises.json", "attestation_digest = D_P de l'exemple", f.Get("attestation_digest").Chaine(), Hex0x(ctx.DP))
	controles := map[string]string{"attestation": "CT-1 AT-3", "approbation": "CT-1 E-9", "ceremonie": "CT-7 CR-11", "inscription": "CT-3 AN-"}
	messageDe := func(v *Value) ([]byte, string) {
		if t := v.Get("text"); t != nil {
			return MessageEIP191Texte(t.Chaine()), "texte"
		}
		d, err := OctetsHex(v.Get("digest").Chaine(), 32)
		if err != nil {
			return nil, err.Error()
		}
		return MessageEIP191(d), "condensé"
	}
	for _, c := range f.Get("cases").Arr {
		nom := c.Get("name").Chaine()
		msg := c.Get("message")
		sig := c.Get("signature").Chaine()
		mOrig, _ := messageDe(msg)
		rec, err := RecouvrerAdresse(mOrig, sig)
		rap.Comparer(fam, nom, "la signature est celle du compte 1 sur le message d'origine", compte, rec+texteErreur(err))
		if k, ok := ctx.Comptes["m/44'/60'/0'/0/1"]; ok && mOrig != nil {
			s, _ := Signer(k, mOrig)
			rap.Comparer(fam, nom, "signature reproduite (RFC 6979)", sig, s)
		}
		switch msg.Get("kind").Chaine() {
		case "attestation":
			rap.Comparer(fam, nom, "message : D_P de l'exemple", msg.Get("digest").Chaine(), Hex0x(ctx.DP))
		case "ceremonie":
			rap.Comparer(fam, nom, "message : D_C de valide-creation-enregistreur", msg.Get("digest").Chaine(), Hex0x(ctx.DCExemple))
		case "inscription":
			t := msg.Get("text").Chaine()
			rap.Constater(fam, nom, "texte d'inscription en noortrace/inscription/v0, préimage d'une autre longueur que 32 octets (EX-7.7)", strings.HasPrefix(t, "noortrace/inscription/v0\n") && len(t) != 32, "")
		default:
			rap.HorsPerimetre(fam, nom, "provenance du condensé "+msg.Get("kind").Chaine(), msg.Get("digest").Chaine(), "D_A de CT-1 §6.4 ou condensé du registre de CT-4 : seule la signature du compte 1 sur ce condensé est vérifiée")
		}
		var mCible []byte
		presente := c.Get("presented_as").Chaine()
		if presente == "attestation" {
			mCible = MessageEIP191(ctx.DP)
		} else {
			mCible, _ = messageDe(c.Get("target"))
			if presente == "ceremonie" {
				rap.Comparer(fam, nom, "cible : D_C de valide-creation-enregistreur", c.Chemin("target", "digest").Chaine(), Hex0x(ctx.DCExemple))
			}
		}
		e := c.Get("expected")
		recC, err := RecouvrerAdresse(mCible, sig)
		rap.Comparer(fam, nom, "adresse recouvrée sur le message présenté", e.Get("recovered").Chaine(), recC+texteErreur(err))
		statut := Reussi
		if recC != compte {
			statut = Echoue
		}
		rap.Comparer(fam, nom, "statut de la vérification qui refuse", e.Get("status").Chaine(), statut)
		if attendu := controles[presente]; strings.HasSuffix(attendu, "-") {
			rap.Constater(fam, nom, "vérification nommée ("+attendu+"…)", strings.HasPrefix(e.Get("check").Chaine(), attendu), e.Get("check").Chaine())
		} else {
			rap.Comparer(fam, nom, "vérification nommée", attendu, e.Get("check").Chaine())
		}
	}
}

// familleMatrice rejoue MX-1 à MX-3, MX-5 et MX-9 (EX-A.23) sur le fichier
// publié et sur les cas de A.8.
func familleMatrice(rap *Rapport, ctx *Contexte) {
	const fam = "matrice"
	sch := ctx.Schemas["matrice-conformite-v0"]
	cm, err := LireContexteMatrice(ctx.Texte)
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	m := lireJSON(rap, filepath.Join(ctx.Racine, "matrice-conformite.json"))
	if m == nil {
		return
	}
	res := VerifierMatrice(m, sch, cm)
	for _, id := range idsMXExecutees {
		rap.Comparer(fam, "matrice-conformite.json", id, "réussie", resumeMX(res[id]))
	}
	for _, id := range []string{"MX-4", "MX-6", "MX-7", "MX-8"} {
		rap.HorsPerimetre(fam, "matrice-conformite.json", id, "réussie", "lit les autres spécifications ou les tables du texte : vérificateur de renvois (EX-A.23)")
	}
	// Exemples annotés de 8.3.
	s83, _ := ctx.Texte.Section("### 8.3")
	if bloc, err := BlocApres(s83, "<!-- schema: matrice-conformite -->"); err == nil {
		ex, err := AnalyserJSONStrict([]byte(bloc))
		if err != nil {
			rap.Erreur("8.3 : %v", err)
		} else {
			rap.Comparer(fam, "texte de CT-7 §8.3", "exemple réduit conforme au schéma", "[]", Liste(sch.Valider(ex)))
			for _, l := range ex.Get("rows").Arr {
				rap.Constater(fam, "texte de CT-7 §8.3", "ligne "+l.Get("id").Chaine()+" = celle du fichier", Egales(l, trouverID(m.Get("rows"), l.Get("id").Chaine())), "différentes")
			}
			for _, t := range ex.Get("texts").Arr {
				rap.Constater(fam, "texte de CT-7 §8.3", "texte "+t.Get("id").Chaine()+" = celui du fichier", Egales(t, trouverID(m.Get("texts"), t.Get("id").Chaine())), "différents")
			}
			rap.Constater(fam, "texte de CT-7 §8.3", "warning = avertissement du fichier", ex.Get("warning").Chaine() == m.Get("warning").Chaine(), "différents")
		}
	}
	if bloc, err := BlocApres(s83, "<!-- schema: matrice-conformite/ligne -->"); err == nil {
		l, err := AnalyserJSONStrict([]byte(bloc))
		def, _ := sch.Sous("#/$defs/ligne")
		if err == nil {
			rap.Comparer(fam, "texte de CT-7 §8.3", "ligne d'exemple conforme à #/$defs/ligne", "[]", Liste(sch.ValiderContre(def, l)))
			rap.Constater(fam, "texte de CT-7 §8.3", "ligne "+l.Get("id").Chaine()+" = celle du fichier", Egales(l, trouverID(m.Get("rows"), l.Get("id").Chaine())), "différentes")
			rap.Comparer(fam, "texte de CT-7 §8.3", "statut dérivé de la ligne d'exemple", l.Get("status").Chaine(), StatutDerive(l))
		}
	}
	// Cas invalides de A.8.
	dir := filepath.Join(ctx.Racine, "matrice", "invalides")
	att := lireJSON(rap, filepath.Join(dir, "attendu.json"))
	if att == nil {
		return
	}
	executees := map[string]bool{}
	for _, id := range idsMXExecutees {
		executees[id] = true
	}
	vus := map[string]bool{}
	for _, c := range att.Get("cases").Arr {
		nom := c.Get("name").Chaine()
		vus[nom] = true
		v := lireJSON(rap, filepath.Join(dir, nom+".json"))
		if v == nil {
			continue
		}
		r := VerifierMatrice(v, sch, cm)
		var attendus, horsP, obtenus []string
		for _, x := range c.Get("failed").Arr {
			if executees[x.Chaine()] {
				attendus = append(attendus, x.Chaine())
			} else {
				horsP = append(horsP, x.Chaine())
			}
		}
		for _, id := range idsMXExecutees {
			if len(r[id]) > 0 {
				obtenus = append(obtenus, id)
			}
		}
		rap.Comparer(fam, "invalides/"+nom, "MX- exécutées en échec (MX-1 à MX-3, MX-5, MX-9)", Liste(attendus), Liste(obtenus))
		if len(horsP) > 0 {
			rap.HorsPerimetre(fam, "invalides/"+nom, "MX- en échec", Liste(horsP), "vérificateur de renvois (EX-A.23)")
		}
	}
	// Table de EX-A.14.
	sA8, _ := ctx.Texte.Section("### A.8")
	tb, err := TableEntete(sA8, "Cas", "Altération")
	if err != nil {
		rap.Erreur("A.8 : %v", err)
		return
	}
	for _, l := range tb.Lignes {
		nom := SansCode(l[0])
		rap.Constater(fam, "invalides/"+nom, "cas exigé par la table d'EX-A.14 publié", vus[nom], "absent de attendu.json")
		for _, c := range att.Get("cases").Arr {
			if c.Get("name").Chaine() == nom {
				annonce := regexp.MustCompile(`MX-[0-9]+`).FindAllString(l[2], -1)
				rap.Comparer(fam, "invalides/"+nom, "MX- en échec : attendu.json = table d'EX-A.14", Liste(annonce), listeValeur(c.Get("failed")))
			}
		}
	}
}

func resumeMX(x []string) string {
	if len(x) == 0 {
		return "réussie"
	}
	sort.Strings(x)
	return "en échec : " + strings.Join(x, " ; ")
}

func trouverID(tab *Value, id string) *Value {
	for _, x := range tab.Arr {
		if x.Get("id").Chaine() == id {
			return x
		}
	}
	return nil
}

// exempleMenaces confronte l'exemple de 3.8 au schéma et au fichier.
func exempleMenaces(rap *Rapport, ctx *Contexte, m *Value) {
	const fam = "menaces"
	s38, err := ctx.Texte.Section("### 3.8")
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	bloc, err := BlocApres(s38, "<!-- schema: modele-menace -->")
	if err != nil {
		rap.Erreur("3.8 : %v", err)
		return
	}
	ex, err := AnalyserJSONStrict([]byte(bloc))
	if err != nil {
		rap.Erreur("3.8 : %v", err)
		return
	}
	rap.Comparer(fam, "texte de CT-7 §3.8", "exemple conforme à modele-menace-v0", "[]", Liste(ctx.Schemas["modele-menace-v0"].Valider(ex)))
	for _, x := range ex.Get("threats").Arr {
		rap.Constater(fam, "texte de CT-7 §3.8", "menace "+x.Get("id").Chaine()+" = celle du fichier", Egales(x, trouverID(m.Get("threats"), x.Get("id").Chaine())), "différentes")
	}
	for _, c := range ex.Get("components").Arr {
		rap.Constater(fam, "texte de CT-7 §3.8", "composant "+c.Get("id").Chaine()+" = celui du fichier", Egales(c, trouverID(m.Get("components"), c.Get("id").Chaine())), "différents")
	}
	for _, k := range []string{"version", "kind", "spec", "spec_version", "date"} {
		rap.Constater(fam, "texte de CT-7 §3.8", k+" = celui du fichier", Egales(ex.Get(k), m.Get(k)), "différents")
	}
}
