// Valeurs déclarées des cas de refus : quand la description d'un cas dit
// comment la valeur déclarée a été faussée (autre identifiant de chaîne,
// autre contrat, autre nonce…), ce vérificateur refait l'altération et
// confronte. La description n'étant pas normative, une altération non
// reproduite est hors périmètre, jamais une discordance.

package main

import (
	"math/big"
)

// alterationDeclaree rend la valeur que la description du cas attribue à
// la valeur déclarée, ou "" si la description ne la détermine pas.
func (c *Ctx) alterationDeclaree(cs Cas) (string, string) {
	in := cs.Input
	h := func(k string, n int) []byte { b, _ := DecoderHexN(in.Get(k).S(), n); return b }
	ct := c.Constantes.Get("contracts")
	adr := func(k string) []byte { b, _ := DecoderHexN(ct.Get(k).S(), 20); return b }
	switch cs.ID {
	case "period-digest-autre-chaine":
		m, err := LireMeta(in.Get("period_meta"))
		if err != nil {
			return "", ""
		}
		return Hex0x(Keccak256(PreimagePeriode(big.NewInt(2121), h("contract", 20), m))), "periodDigest pour l'identifiant EVM 2121"
	case "register-digest-autre-contrat":
		pre, e := PreimageInscription(c.ChainID, adr("period_registry"), h("org_id", 32), h("journal_id", 32), h("chain_key", 20), h("ed25519_public_key", 32))
		if e != nil {
			return "", ""
		}
		return Hex0x(Keccak256(pre)), "registerDigest à l'adresse de PeriodRegistry"
	case "revoke-digest-autre-inscription":
		reg, err := Decimal(in.Get("registered_at").S())
		if err != nil {
			return "", ""
		}
		pre, e := PreimageRevocation(c.ChainID, h("contract", 20), h("org_id", 32), h("chain_key", 20), new(big.Int).Add(reg, big.NewInt(1)))
		if e != nil {
			return "", ""
		}
		return Hex0x(Keccak256(pre)), "revokeDigest pour registeredAt + 1"
	case "revoke-ancre-etiquette-ancre":
		dt := Keccak256([]byte("noortrace/periode/v0"))
		return Hex0x(Keccak256(PreimageAncre(c.ChainID, h("contract", 20), h("fingerprint", 32), dt))), "anchorDigest de la même empreinte"
	case "admin-op-autre-nonce":
		pre, e := PreimageAdmin(c.ChainID, h("contract", 20), in.Get("op").S(), h("arg", 32), big.NewInt(1))
		if e != nil {
			return "", ""
		}
		return Hex0x(Keccak256(pre)), "adminOpDigest au nonce 1"
	case "declaree-racine":
		mans := c.manifestesCT1()
		if m, ok := mans[in.Get("period_hash").S()]; ok {
			r, _ := DecoderHexN(m.Get("root").S(), 32)
			return Hex0x(Keccak256(r)), "keccak256 de la racine du manifeste"
		}
	case "declaree-ordre-inverse":
		return Hex0x(Keccak256(concat(h("journal_id", 32), h("org_id", 32), h("period_hash", 32)))), "keccak256(journal_id ‖ org_id ‖ periodHash)"
	case "declaree-sha256":
		return Hex0x(Sha256(concat(h("org_id", 32), h("journal_id", 32), h("period_hash", 32)))), "SHA-256 de la préimage"
	}
	return "", ""
}

// comparerAlteration confronte la valeur déclarée d'un cas de refus à
// l'altération que sa description nomme.
func (c *Ctx) comparerAlteration(f *Famille, cs Cas, cle string) {
	dec := cs.Input.Get(cle)
	if dec == nil {
		return
	}
	v, quoi := c.alterationDeclaree(cs)
	if v == "" {
		f.Hors(cs.ID, cle+" déclaré", "altération que la description ne détermine pas")
		return
	}
	if v != dec.S() {
		f.Hors(cs.ID, cle+" déclaré", "altération décrite ("+quoi+") non reproduite : "+v)
		return
	}
	f.Comparer(cs.ID, cle+" déclaré = "+quoi, dec.S(), v, "EX-A.3")
}
