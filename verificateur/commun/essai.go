package commun

// Pièces d'essai (CT-6 section 6.10, complément du 2026-11-19, décision du
// porteur) : valeurs exactes qui désignent une pièce d'essai (EX-6.23),
// détails des avertissements AV-T-5, AV-R-4, AV-N-1 et AV-N-2 (EX-6.24), et
// contrôles réussis sans valeur de preuve (EX-6.25). Aucune pièce n'est
// reconnue d'après un nom ou un texte libre.

import "strings"

func ensemble(valeurs ...string) map[string]bool {
	m := make(map[string]bool, len(valeurs))
	for _, v := range valeurs {
		m[v] = true
	}
	return m
}

// certificatsEssai : SHA-256 du DER des seize certificats de
// spec/vecteurs/ct-6/rfc3161/cles/ et de l'AC d'exemple de CT-6 §12.3.
var certificatsEssai = ensemble(
	"0x56ae2b379606d0aee499f5d790f35cc9a41ee6dbc63e511f5f2c5ac73399b568",
	"0xf9e8f8ac115234297bfd817696c83a4eab398ee1c028931d09b34be6b4335037",
	"0xf34bca8cb29c2632ec209abf39fb912c0eaadc7bbf237deaeb41e51310f98739",
	"0x77be4a251aa3cdd0ce67e07eb4b3be46b906d9f10a1687a22d8f4a2cc13ef078",
	"0x243795c7795d2372773329da9efba1de71ddf175d0f0d5ec9b744618e62e7327",
	"0xb3bed2e9b5a52e4a9423dc420194d2c1b0b090bb625fac40e14ed07d3200f597",
	"0x8bcda2d914e55fe43e07f96102b2ebfee03cba768c55f18dace7f295a3c93332",
	"0xa39159bef83a32855479074287e8030987fc103259c63eac85437c860a7f7e6e",
	"0x3b2070b9e823b69157f06e7ab4c8d2f8d43e6e1e9033b4280a0ac6d57c3580bd",
	"0xe91135578a497e9f25f34c961e1b860e844f9a15bdf657e08e255c820699d002",
	"0xe1d773f9b29af5614c521969b98ffdcb3a484ec98e2f2ff843f001c637d89d3a",
	"0x08666cf01c0ef9fc7bc5279264c186a414fe5774cb05280931c3ec9e53c66b14",
	"0x17b014380b0c82f5a903597ff629c3605625d621588098c62fc48c5f0fee5123",
	"0x3ac1e377b94a494fabfe27654bec6917ebe83ab5dc75a7642f74ff8966173a9b",
	"0x69ada0c156e7ecd5b363da0a77b947e550368832e02c535cfe991b5b02041e84",
	"0x0059fa87b4b02432ab3c2cbedbabaefe0e4b4839352921385c6fb1df1035c3a9",
	"0x89873f3fcb40f2b42c29e5457dea05ef5e41281451afccbec2934a80eb7a5539",
)

// chainesEssai : identifiant BFT du réseau de développement (CT-4).
var chainesEssai = ensemble("noortrace-2124-dev")

// clesEnregistreurEssai : clés publiques de rec-test-01 à rec-test-03.
var clesEnregistreurEssai = ensemble(
	"0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045",
	"0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3",
	"0x7fcebb9e8efd62d13a17c830ad33739c1de7fe9f1458701cb739ae15e9e62cd6",
)

// clesChaineEssai : clés de chaîne de rec-test-01 à rec-test-03.
var clesChaineEssai = ensemble(
	"0xaa2a59656361352e96ef2eed355316ef8b29dab7",
	"0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49",
	"0xe2bdcef6264103ab6c88fa3c1b5a2ceacd995b22",
)

// approbateursEssai : comptes 0 à 19 du mnémonique Hardhat par défaut.
var approbateursEssai = ensemble(
	"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
	"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
	"0x15d34aaf54267db7d7c367839aaf71a00a2c6a65", "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
	"0x976ea74026e726554db657fa54763abd0c3a0aa9", "0x14dc79964da2c08b23698b3d3cc7ca32193d9955",
	"0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f", "0xa0ee7a142d267c1f36714e4a8f75612f20a79720",
	"0xbcd4042de499d14e55001ccbb24a551f3b954096", "0x71be63f3384f5fb98995898a86b02fb2426c5788",
	"0xfabb0ac9d68b0b445fb7357272ff202c5651694a", "0x1cbd3b2770909d4e10f157cabc84c7264073c9ec",
	"0xdf3e18d64bc6a983f673ab319ccae4f1a57c7097", "0xcd3b766ccdd6ae721141f452c550ca635964ce71",
	"0x2546bcd3c84621e976d8185a91a922ae77ecec30", "0xbda5747bfd65f08deb54cb465eb87d40e51b197e",
	"0xdd2fd4581271e230360230f9337d5c0430bf44c0", "0x8626f6940e2eb28930efb4cef49b2d1f2c9c1199",
)

// EstCertificatEssai : SHA-256 (hexadécimal 0x…) d'un certificat d'essai.
func EstCertificatEssai(sha256Hex string) bool { return certificatsEssai[strings.ToLower(sha256Hex)] }

// EstChaineEssai : identifiant BFT d'un registre d'essai (comparaison exacte).
func EstChaineEssai(chainID string) bool { return chainesEssai[chainID] }

// EstCleEnregistreurEssai : clé publique Ed25519 (0x…) d'enregistreur d'essai.
func EstCleEnregistreurEssai(cle string) bool { return clesEnregistreurEssai[strings.ToLower(cle)] }

// EstCleChaineEssai : clé de chaîne (0x…, 20 octets) d'essai.
func EstCleChaineEssai(cle string) bool { return clesChaineEssai[strings.ToLower(cle)] }

// EstApprobateurEssai : adresse (0x…) d'approbateur d'essai.
func EstApprobateurEssai(adresse string) bool { return approbateursEssai[strings.ToLower(adresse)] }

// DetailAutoriteEssai : détail d'AV-T-5.
func DetailAutoriteEssai(nom, sha string) Texte {
	return T("autorité "+nom+" : certificat d'essai "+sha+", sans valeur probante hors des tests",
		"authority "+nom+": test certificate "+sha+", no evidential value outside tests")
}

// DetailRegistreEssai : détail d'AV-R-4.
func DetailRegistreEssai(chainID string) Texte {
	return T("registre "+chainID+" : réseau de développement, sans valeur probante hors des tests",
		"registry "+chainID+": development network, no evidential value outside tests")
}

// DetailCleEssai : détail d'AV-N-1 pour une clé d'enregistreur ; role vaut
// "evenement", "manifeste" ou "point".
func DetailCleEssai(keyID, role string) Texte {
	fr := map[string]string{"evenement": "événement", "manifeste": "manifeste", "point": "point de contrôle"}[role]
	en := map[string]string{"evenement": "event", "manifeste": "manifest", "point": "checkpoint"}[role]
	return T("clé d'enregistreur "+keyID+" ("+fr+") : clé d'essai publiée, sans valeur probante hors des tests",
		"recorder key "+keyID+" ("+en+"): published test key, no evidential value outside tests")
}

// DetailCleChaineEssai : détail d'AV-N-1 pour une clé de chaîne (N-4).
func DetailCleChaineEssai(chainKey, keyID string) Texte {
	return T("clé de chaîne "+chainKey+" de "+keyID+" : clé d'essai publiée, sans valeur probante hors des tests",
		"chain key "+chainKey+" of "+keyID+": published test key, no evidential value outside tests")
}

// DetailApprobateurEssai : détail d'AV-N-2.
func DetailApprobateurEssai(adresse string) Texte {
	return T("approbateur "+adresse+" : compte d'essai publié, sans valeur probante hors des tests",
		"approver "+adresse+": published test account, no evidential value outside tests")
}

// ControlesSansValeur applique EX-6.25 : contrôles réussis (reussi[n]) sans
// valeur de preuve, d'après les avertissements et, pour le contrôle 7, les
// approbateurs et le seuil requis. Rend les numéros, croissants.
func ControlesSansValeur(reussi [9]bool, avert []Avertissement, approbateurs []string, requis int64) []int {
	a := func(id string, checks ...string) bool {
		for _, w := range avert {
			if w.ID != id {
				continue
			}
			for _, c := range checks {
				if w.Verification == c {
					return true
				}
			}
		}
		return false
	}
	var out []int
	if reussi[4] && a("AV-T-5", "T-7") {
		out = append(out, 4)
	}
	if reussi[5] && a("AV-O-3", "O-5") {
		out = append(out, 5)
	}
	if reussi[6] && a("AV-N-1", "E-8", "P-5") {
		out = append(out, 6)
	}
	if reussi[7] && a("AV-N-2", "E-9") {
		hors := map[string]bool{}
		for _, x := range approbateurs {
			if !EstApprobateurEssai(x) {
				hors[strings.ToLower(x)] = true
			}
		}
		if int64(len(hors)) < requis {
			out = append(out, 7)
		}
	}
	if reussi[8] && (a("AV-R-4", "R-4") || a("AV-N-1", "N-4")) {
		out = append(out, 8)
	}
	return out
}
