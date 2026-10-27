// Clés de test publiées (CT-7 EX-4.10, EX-A.7, RV-9) : cles-de-test.json
// liste, par source, chaque clé publique de test des vecteurs. Ce module la
// recalcule là où une dérivation est écrite dans le texte qu'il lit :
//   - ct-1 : graine Ed25519 = SHA-256(UTF-8(étiquette)), clé publique de la
//     RFC 8032 (CT-1 §13) ;
//   - ct-3 : comptes du mnémonique public de spec/vecteurs/ct-3/constantes.json
//     au chemin donné (BIP-39, BIP-32 ; CT-7 EX-A.1) ;
//   - ct-6 : SHA-256 du SubjectPublicKeyInfo des fichiers PEM de
//     spec/vecteurs/ct-6/<étiquette> (certificat ou clé privée PKCS#8).
// Pour ct-4, dont CT-7 ne donne pas la dérivation (CT-4 annexe A.2), seule
// la cohérence interne est recalculée : point de la courbe et adresse
// dérivée pour secp256k1, longueur pour Ed25519 ; la dérivation depuis
// l'étiquette est rapportée hors périmètre.

package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// spkiDePEM rend le SubjectPublicKeyInfo DER d'un fichier PEM : certificat,
// ou clé privée PKCS#8 dont on tire la clé publique.
func spkiDePEM(chemin string) ([]byte, error) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	bloc, _ := pem.Decode(b)
	if bloc == nil {
		return nil, fmt.Errorf("%s : aucun bloc PEM", chemin)
	}
	switch bloc.Type {
	case "CERTIFICATE":
		return spkiDeCertificat(bloc.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(bloc.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s : clé sans partie publique", chemin)
		}
		return x509.MarshalPKIXPublicKey(s.Public())
	}
	return nil, fmt.Errorf("%s : bloc PEM %q non pris en charge", chemin, bloc.Type)
}

// spkiDeCertificat lit le septième champ de tbsCertificate (RFC 5280
// §4.1 : version facultative [0], serialNumber, signature, issuer,
// validity, subject, subjectPublicKeyInfo) sans décoder les noms : un
// certificat de test porte volontairement un nom mal formé (CN en UTF-8
// invalide), que crypto/x509 refuse.
func spkiDeCertificat(der []byte) ([]byte, error) {
	var cert, tbs asn1.RawValue
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, err
	}
	if _, err := asn1.Unmarshal(cert.Bytes, &tbs); err != nil {
		return nil, err
	}
	reste := tbs.Bytes
	var champs []asn1.RawValue
	for len(reste) > 0 {
		var c asn1.RawValue
		r, err := asn1.Unmarshal(reste, &c)
		if err != nil {
			return nil, err
		}
		champs = append(champs, c)
		reste = r
	}
	if len(champs) > 0 && champs[0].Class == asn1.ClassContextSpecific && champs[0].Tag == 0 {
		champs = champs[1:]
	}
	if len(champs) < 6 {
		return nil, fmt.Errorf("tbsCertificate de %d champs", len(champs))
	}
	return champs[5].FullBytes, nil
}

// VerifierClesDeTest confronte cles-de-test.json aux clés recalculées.
func VerifierClesDeTest(rap *Rapport, racine string, comptes map[string][]byte) {
	const fam = "cles-de-test"
	v := lireJSON(rap, filepath.Join(racine, "cles-de-test.json"))
	if v == nil {
		return
	}
	cles := v.Get("keys").Arr
	sources := map[string]int{}
	for _, k := range cles {
		src, label, algo := k.Get("source").Chaine(), k.Get("label").Chaine(), k.Get("algorithm").Chaine()
		sources[src]++
		vec := src + " " + label
		pub := k.Get("public_key").Chaine()
		switch {
		case src == "ct-1" && algo == "ed25519":
			graine := SHA256([]byte(label))
			p := ed25519.NewKeyFromSeed(graine).Public().(ed25519.PublicKey)
			rap.Comparer(fam, vec, "clé publique Ed25519 (graine SHA-256 de l'étiquette, CT-1 §13)", pub, Hex0x(p))
		case src == "ct-3" && algo == "secp256k1":
			prive, ok := comptes[label]
			if !ok {
				rap.Erreur("%s : chemin de dérivation non recalculé", vec)
				continue
			}
			p, _ := ClePubliqueNonCompressee(prive)
			a, _ := AdresseDeCleNonCompressee(p)
			rap.Comparer(fam, vec, "clé publique (BIP-32 du mnémonique de ct-3)", pub, Hex0x(p))
			rap.Comparer(fam, vec, "adresse", k.Get("address").Chaine(), a)
		case src == "ct-6" && algo == "rsa":
			spki, err := spkiDePEM(filepath.Join(racine, "..", "ct-6", filepath.FromSlash(label)))
			if err != nil {
				rap.Erreur("%s : %v", vec, err)
				continue
			}
			rap.Comparer(fam, vec, "SHA-256 du SubjectPublicKeyInfo", k.Get("spki_sha256").Chaine(), Hex0x(SHA256(spki)))
		case algo == "secp256k1":
			b, err := OctetsHex(pub, 65)
			if err != nil {
				rap.Comparer(fam, vec, "clé publique secp256k1 non compressée", "65 octets", err.Error())
				continue
			}
			a, err := AdresseDeCleNonCompressee(b)
			if err != nil {
				rap.Comparer(fam, vec, "point de la courbe", "oui", err.Error())
				continue
			}
			rap.Comparer(fam, vec, "adresse dérivée de la clé publique", k.Get("address").Chaine(), a)
			rap.HorsPerimetre(fam, vec, "clé publique depuis l'étiquette", pub, "dérivation de CT-4 annexe A.2, que le texte de CT-7 ne fixe pas")
		case algo == "ed25519":
			b, err := OctetsHex(pub, 32)
			rap.Constater(fam, vec, "clé publique Ed25519 de 32 octets", err == nil && len(b) == 32, texteErreur(err))
			rap.HorsPerimetre(fam, vec, "clé publique depuis l'étiquette", pub, "dérivation de CT-4 annexe A.2, que le texte de CT-7 ne fixe pas")
		default:
			rap.Erreur("%s : source ou algorithme inattendu (%s)", vec, algo)
		}
	}
	for _, s := range []string{"ct-1", "ct-3", "ct-4", "ct-6"} {
		rap.Constater(fam, "cles-de-test.json", "source "+s+" présente (EX-A.7)", sources[s] > 0, "aucune clé")
	}
}
