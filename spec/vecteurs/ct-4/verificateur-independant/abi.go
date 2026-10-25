// Encodage des appels selon CT-4 §6.7 : sélecteur = 4 premiers octets de
// keccak256(utf8(signature)) (6.7.1) ; arguments selon les règles 1 à 5 de
// 6.7.2 (valeurs statiques en place, valeurs dynamiques remplacées dans la
// tête par leur position, comptée depuis le début de la tête, et écrites
// dans la queue) ; T(meta) et E(meta) = u256(0x20) ‖ T(meta).

package main

import (
	"errors"
	"fmt"
	"math/big"
)

// Signatures des fonctions écrites par les outils (table de 6.7.1).
var signaturesFonctions = map[string]string{
	"anchor":              "anchor(bytes32,bytes32,address,(uint8,bytes32,bytes32))",
	"revoke":              "revoke(bytes32,(uint8,bytes32,bytes32))",
	"submitPeriod":        "submitPeriod((bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,string),(uint8,bytes32,bytes32)[])",
	"registerRecorder":    "registerRecorder(bytes32,bytes32,address,bytes32,(uint8,bytes32,bytes32)[])",
	"revokeRecorder":      "revokeRecorder(bytes32,address,(uint8,bytes32,bytes32)[])",
	"setCuratorSet":       "setCuratorSet(bytes32,address)",
	"addCuratorSigned":    "addCuratorSigned(address,uint256,(uint8,bytes32,bytes32))",
	"removeCuratorSigned": "removeCuratorSigned(address,uint256,(uint8,bytes32,bytes32))",
	"setThresholdSigned":  "setThresholdSigned(uint256,uint256,(uint8,bytes32,bytes32))",
	"proposeAdminSigned":  "proposeAdminSigned(address,uint256,(uint8,bytes32,bytes32))",
	"acceptAdminSigned":   "acceptAdminSigned(uint256,(uint8,bytes32,bytes32))",
}

// Selecteur rend les 4 premiers octets de keccak256(utf8(signature)).
func Selecteur(sig string) []byte { return Keccak256([]byte(sig))[:4] }

// MetaPeriode est PeriodMeta (CT-4 6.6.1, schéma meta_periode).
type MetaPeriode struct {
	OrgID, JournalID, PeriodHash, Root        []byte
	PeriodStart, PeriodEnd, FirstSeq, LastSeq *big.Int
	Version                                   *big.Int
	URI                                       string
}

// LireMeta lit un objet meta_periode ; les bornes sont des entiers décimaux
// en chaînes, version un entier JSON.
func LireMeta(o *Value) (MetaPeriode, error) {
	var m MetaPeriode
	if o == nil || o.Kind != KindObject {
		return m, errors.New("period_meta : objet attendu")
	}
	var err error
	for _, p := range []struct {
		cle string
		dst *[]byte
	}{{"org_id", &m.OrgID}, {"journal_id", &m.JournalID}, {"period_hash", &m.PeriodHash}, {"root", &m.Root}} {
		s, err := Champ(o, p.cle)
		if err != nil {
			return m, err
		}
		if *p.dst, err = DecoderHexN(s, 32); err != nil {
			return m, err
		}
	}
	for _, p := range []struct {
		cle string
		dst **big.Int
	}{{"period_start", &m.PeriodStart}, {"period_end", &m.PeriodEnd}, {"first_seq", &m.FirstSeq}, {"last_seq", &m.LastSeq}} {
		s, err := Champ(o, p.cle)
		if err != nil {
			return m, err
		}
		if *p.dst, err = Decimal(s); err != nil {
			return m, err
		}
	}
	if m.Version, err = EntierChamp(o, "version"); err != nil {
		return m, err
	}
	if m.URI, err = Champ(o, "uri"); err != nil {
		return m, err
	}
	return m, nil
}

// chaineABI encode une string : u256(longueur) ‖ octets complétés à un
// multiple de 32 (règle 2).
func chaineABI(s string) []byte {
	b := []byte(s)
	out := u256i(uint64(len(b)))
	out = append(out, b...)
	if r := len(b) % 32; r != 0 {
		out = append(out, make([]byte, 32-r)...)
	}
	return out
}

// TMeta rend T(meta) (règle 4).
func TMeta(m MetaPeriode) []byte {
	return concat(m.OrgID, m.JournalID, m.PeriodHash, m.Root, u256(m.PeriodStart), u256(m.PeriodEnd),
		u256(m.FirstSeq), u256(m.LastSeq), u256(m.Version), u256i(0x140), chaineABI(m.URI))
}

// EMeta rend E(meta) = abi.encode(meta) = u256(0x20) ‖ T(meta).
func EMeta(m MetaPeriode) []byte { return concat(u256i(0x20), TMeta(m)) }

// Sig3 est le tuple statique (uint8 v, bytes32 r, bytes32 s).
func sig3(s SignatureEVM) ([]byte, error) {
	if s.V < 0 || s.V > 255 {
		return nil, fmt.Errorf("v = %d ne tient pas dans un uint8", s.V)
	}
	if s.R.Sign() < 0 || s.R.BitLen() > 256 || s.S.Sign() < 0 || s.S.BitLen() > 256 {
		return nil, errors.New("r ou s hors de 32 octets")
	}
	return concat(u256i(uint64(s.V)), u256(s.R), u256(s.S)), nil
}

func tableauSig(sigs []SignatureEVM) ([]byte, error) {
	out := u256i(uint64(len(sigs)))
	for _, s := range sigs {
		b, err := sig3(s)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

func mot20(a []byte) []byte { return concat(make([]byte, 12), a) }

// lireSignatures lit un tableau d'objets { v, r, s }.
func lireSignatures(v *Value) ([]SignatureEVM, error) {
	if v == nil || v.Kind != KindArray {
		return nil, errors.New("signatures : tableau attendu")
	}
	var out []SignatureEVM
	for _, o := range v.Arr {
		s, _, err := LireSignature(o)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func hexArg(a *Value, cle string, n int) ([]byte, error) {
	s, err := Champ(a, cle)
	if err != nil {
		return nil, err
	}
	return DecoderHexN(s, n)
}

func decArg(a *Value, cle string) (*big.Int, error) {
	s, err := Champ(a, cle)
	if err != nil {
		return nil, err
	}
	return Decimal(s)
}

// DonneesAppel construit les données d'appel d'une fonction de la table de
// 6.7.2 depuis ses arguments (objet args des vecteurs).
func DonneesAppel(fonction string, a *Value) ([]byte, error) {
	sigf, ok := signaturesFonctions[fonction]
	if !ok {
		return nil, fmt.Errorf("fonction %q hors de la table de 6.7.1", fonction)
	}
	sel := Selecteur(sigf)
	switch fonction {
	case "anchor":
		fp, err := hexArg(a, "fingerprint", 32)
		if err != nil {
			return nil, err
		}
		dt, err := hexArg(a, "doc_type", 32)
		if err != nil {
			return nil, err
		}
		is, err := hexArg(a, "issuer", 20)
		if err != nil {
			return nil, err
		}
		s, _, err := LireSignature(a.Get("signature"))
		if err != nil {
			return nil, err
		}
		sb, err := sig3(s)
		if err != nil {
			return nil, err
		}
		return concat(sel, fp, dt, mot20(is), sb), nil
	case "revoke":
		fp, err := hexArg(a, "fingerprint", 32)
		if err != nil {
			return nil, err
		}
		s, _, err := LireSignature(a.Get("signature"))
		if err != nil {
			return nil, err
		}
		sb, err := sig3(s)
		if err != nil {
			return nil, err
		}
		return concat(sel, fp, sb), nil
	case "registerRecorder":
		org, err := hexArg(a, "org_id", 32)
		if err != nil {
			return nil, err
		}
		jou, err := hexArg(a, "journal_id", 32)
		if err != nil {
			return nil, err
		}
		ck, err := hexArg(a, "chain_key", 20)
		if err != nil {
			return nil, err
		}
		ed, err := hexArg(a, "ed25519_public_key", 32)
		if err != nil {
			return nil, err
		}
		sigs, err := lireSignatures(a.Get("signatures"))
		if err != nil {
			return nil, err
		}
		tb, err := tableauSig(sigs)
		if err != nil {
			return nil, err
		}
		return concat(sel, org, jou, mot20(ck), ed, u256i(0xa0), tb), nil
	case "revokeRecorder":
		org, err := hexArg(a, "org_id", 32)
		if err != nil {
			return nil, err
		}
		ck, err := hexArg(a, "chain_key", 20)
		if err != nil {
			return nil, err
		}
		sigs, err := lireSignatures(a.Get("signatures"))
		if err != nil {
			return nil, err
		}
		tb, err := tableauSig(sigs)
		if err != nil {
			return nil, err
		}
		return concat(sel, org, mot20(ck), u256i(0x60), tb), nil
	case "submitPeriod":
		m, err := LireMeta(a.Get("period_meta"))
		if err != nil {
			return nil, err
		}
		sigs, err := lireSignatures(a.Get("signatures"))
		if err != nil {
			return nil, err
		}
		tb, err := tableauSig(sigs)
		if err != nil {
			return nil, err
		}
		t := TMeta(m)
		return concat(sel, u256i(0x40), u256i(uint64(0x40+len(t))), t, tb), nil
	case "setCuratorSet":
		org, err := hexArg(a, "org_id", 32)
		if err != nil {
			return nil, err
		}
		cs, err := hexArg(a, "curator_set", 20)
		if err != nil {
			return nil, err
		}
		return concat(sel, org, mot20(cs)), nil
	case "addCuratorSigned", "removeCuratorSigned", "proposeAdminSigned":
		cle := "curator"
		if fonction == "proposeAdminSigned" {
			cle = "new_admin"
		}
		ad, err := hexArg(a, cle, 20)
		if err != nil {
			return nil, err
		}
		n, err := decArg(a, "nonce")
		if err != nil {
			return nil, err
		}
		s, _, err := LireSignature(a.Get("signature"))
		if err != nil {
			return nil, err
		}
		sb, err := sig3(s)
		if err != nil {
			return nil, err
		}
		return concat(sel, mot20(ad), u256(n), sb), nil
	case "setThresholdSigned":
		t, err := decArg(a, "threshold")
		if err != nil {
			return nil, err
		}
		n, err := decArg(a, "nonce")
		if err != nil {
			return nil, err
		}
		s, _, err := LireSignature(a.Get("signature"))
		if err != nil {
			return nil, err
		}
		sb, err := sig3(s)
		if err != nil {
			return nil, err
		}
		return concat(sel, u256(t), u256(n), sb), nil
	case "acceptAdminSigned":
		n, err := decArg(a, "nonce")
		if err != nil {
			return nil, err
		}
		s, _, err := LireSignature(a.Get("signature"))
		if err != nil {
			return nil, err
		}
		sb, err := sig3(s)
		if err != nil {
			return nil, err
		}
		return concat(sel, u256(n), sb), nil
	}
	return nil, fmt.Errorf("fonction %q non traitée", fonction)
}

// LongueurAttendue rend la longueur de la table de 6.7.2 pour une fonction,
// k signatures et une uri de longueur lu.
func LongueurAttendue(fonction string, k, lu int) int {
	switch fonction {
	case "anchor":
		return 196
	case "revoke", "acceptAdminSigned":
		return 132
	case "registerRecorder":
		return 196 + 96*k
	case "revokeRecorder":
		return 132 + 96*k
	case "submitPeriod":
		l := 352 + 32*((lu+31)/32)
		return 100 + l + 96*k
	case "setCuratorSet":
		return 68
	case "addCuratorSigned", "removeCuratorSigned", "proposeAdminSigned", "setThresholdSigned":
		return 164
	}
	return -1
}

// ArgumentsConstructeur encode les arguments d'un constructeur (6.7.2, règle
// 3) : un mot pour CuratorSetRegistry, PeriodRegistry et RecorderRegistry ;
// pour CuratorSet(address initialAdmin, address[] initialCurators, uint256
// initialThreshold) (5.1), a20 en place ‖ u256(0x60) ‖ u256(t) ‖ u256(k) ‖
// k × (12 octets nuls ‖ a20), soit 128 + 32k octets.
func ArgumentsConstructeur(contrat string, a *Value) ([]byte, error) {
	switch contrat {
	case "AttestationRegistry":
		if a != nil && a.Kind == KindObject && len(a.Obj) != 0 {
			return nil, errors.New("AttestationRegistry n'a aucun argument")
		}
		return []byte{}, nil
	case "CuratorSetRegistry":
		ad, err := hexArg(a, "initial_admin", 20)
		if err != nil {
			return nil, err
		}
		return mot20(ad), nil
	case "PeriodRegistry", "RecorderRegistry":
		ad, err := hexArg(a, "curator_set_registry", 20)
		if err != nil {
			return nil, err
		}
		return mot20(ad), nil
	case "CuratorSet":
		ad, err := hexArg(a, "initial_admin", 20)
		if err != nil {
			return nil, err
		}
		mem := a.Get("members")
		if mem == nil || mem.Kind != KindArray {
			return nil, errors.New("members : tableau attendu")
		}
		t, err := EntierChamp(a, "threshold")
		if err != nil {
			return nil, err
		}
		queue := u256i(uint64(len(mem.Arr)))
		for _, m := range mem.Arr {
			b, err := DecoderHexN(m.S(), 20)
			if err != nil {
				return nil, err
			}
			queue = append(queue, mot20(b)...)
		}
		return concat(mot20(ad), u256i(0x60), u256(t), queue), nil
	}
	return nil, fmt.Errorf("contrat %q inconnu", contrat)
}

// DecoderAppel relit des données d'appel d'une fonction de la table et les
// réécrit selon 6.7.2 : des données conformes se réécrivent à l'identique
// (RG-14, contrôle d'une transaction par RG-15).
func DecoderAppel(d []byte) (string, error) {
	if len(d) < 4 {
		return "", errors.New("données d'appel de moins de 4 octets")
	}
	var fonction string
	for f, s := range signaturesFonctions {
		if egal(Selecteur(s), d[:4]) {
			fonction = f
		}
	}
	if fonction == "" {
		return "", fmt.Errorf("sélecteur %s hors de la table de 6.7.1", Hex0x(d[:4]))
	}
	corps := d[4:]
	mot := func(i int) ([]byte, error) {
		if 32*(i+1) > len(corps) {
			return nil, errors.New("données tronquées")
		}
		return corps[32*i : 32*(i+1)], nil
	}
	entier := func(i int) (int, error) {
		w, err := mot(i)
		if err != nil {
			return 0, err
		}
		n := new(big.Int).SetBytes(w)
		if n.BitLen() > 31 {
			return 0, errors.New("entier démesuré")
		}
		return int(n.Int64()), nil
	}
	var k, lu int
	switch fonction {
	case "registerRecorder":
		n, err := entier(5)
		if err != nil {
			return "", err
		}
		k = n
	case "revokeRecorder":
		n, err := entier(3)
		if err != nil {
			return "", err
		}
		k = n
	case "submitPeriod":
		// tête de 2 mots, T(meta) dont le mot 9 est la position de uri et
		// le mot 10 sa longueur ; puis k.
		n, err := entier(2 + 10)
		if err != nil {
			return "", err
		}
		lu = n
		l := 352 + 32*((lu+31)/32)
		kk, err := entier((64 + l) / 32)
		if err != nil {
			return "", err
		}
		k = kk
	}
	if want := LongueurAttendue(fonction, k, lu); want != len(d) {
		return fonction, fmt.Errorf("%d octets au lieu de %d (table de 6.7.2)", len(d), want)
	}
	// Réécriture : on reconstruit les arguments puis on réencode.
	args := Objet()
	sigAt := func(off int) *Value {
		v := new(big.Int).SetBytes(corps[off : off+32])
		return Objet("v", &Value{Kind: KindNumber, Num: v.String()}, "r", Chaine(Hex0x(corps[off+32:off+64])), "s", Chaine(Hex0x(corps[off+64:off+96])))
	}
	sigsAt := func(off, k int) *Value {
		t := Tableau()
		for i := 0; i < k; i++ {
			t.Arr = append(t.Arr, sigAt(off+32+96*i))
		}
		return t
	}
	adr := func(w []byte) *Value { return Chaine(Hex0x(w[12:])) }
	h32 := func(i int) *Value { return Chaine(Hex0x(corps[32*i : 32*(i+1)])) }
	dec := func(i int) *Value { return Chaine(new(big.Int).SetBytes(corps[32*i : 32*(i+1)]).String()) }
	switch fonction {
	case "anchor":
		args = Objet("fingerprint", h32(0), "doc_type", h32(1), "issuer", adr(corps[64:96]), "signature", sigAt(96))
	case "revoke":
		args = Objet("fingerprint", h32(0), "signature", sigAt(32))
	case "registerRecorder":
		args = Objet("org_id", h32(0), "journal_id", h32(1), "chain_key", adr(corps[64:96]), "ed25519_public_key", h32(3), "signatures", sigsAt(160, k))
	case "revokeRecorder":
		args = Objet("org_id", h32(0), "chain_key", adr(corps[32:64]), "signatures", sigsAt(96, k))
	case "submitPeriod":
		t := corps[64:]
		uri := string(t[352 : 352+lu])
		meta := Objet("org_id", Chaine(Hex0x(t[0:32])), "journal_id", Chaine(Hex0x(t[32:64])), "period_hash", Chaine(Hex0x(t[64:96])),
			"root", Chaine(Hex0x(t[96:128])), "period_start", Chaine(new(big.Int).SetBytes(t[128:160]).String()),
			"period_end", Chaine(new(big.Int).SetBytes(t[160:192]).String()), "first_seq", Chaine(new(big.Int).SetBytes(t[192:224]).String()),
			"last_seq", Chaine(new(big.Int).SetBytes(t[224:256]).String()), "version", &Value{Kind: KindNumber, Num: new(big.Int).SetBytes(t[256:288]).String()},
			"uri", Chaine(uri))
		l := 352 + 32*((lu+31)/32)
		args = Objet("period_meta", meta, "signatures", sigsAt(64+l, k))
	case "setCuratorSet":
		args = Objet("org_id", h32(0), "curator_set", adr(corps[32:64]))
	case "addCuratorSigned", "removeCuratorSigned":
		args = Objet("curator", adr(corps[0:32]), "nonce", dec(1), "signature", sigAt(64))
	case "proposeAdminSigned":
		args = Objet("new_admin", adr(corps[0:32]), "nonce", dec(1), "signature", sigAt(64))
	case "setThresholdSigned":
		args = Objet("threshold", dec(0), "nonce", dec(1), "signature", sigAt(64))
	case "acceptAdminSigned":
		args = Objet("nonce", dec(0), "signature", sigAt(32))
	}
	re, err := DonneesAppel(fonction, args)
	if err != nil {
		return fonction, err
	}
	if !egal(re, d) {
		return fonction, errors.New("les données ne se réécrivent pas à l'identique selon 6.7.2")
	}
	return fonction, nil
}
