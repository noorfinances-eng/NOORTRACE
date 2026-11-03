// Clés de test publiées (CT-7 EX-4.10, EX-A.7, RV-9) : cles-de-test.json
// liste, par source, chaque clé publique de test des vecteurs. Ce module la
// recalcule là où une dérivation est écrite dans le texte qu'il lit :
//   - ct-1 : graine Ed25519 = SHA-256(UTF-8(étiquette)), clé publique de la
//     RFC 8032 (CT-1 §13) ;
//   - ct-3 : comptes du mnémonique public de spec/vecteurs/ct-3/constantes.json
//     au chemin donné (BIP-39, BIP-32 ; CT-7 EX-A.1) ;
//   - ct-6 : quel que soit l'algorithme (rsa, ecdsa_p256, ed25519), une seule
//     forme, spki_sha256 = SHA-256 du SubjectPublicKeyInfo DER des fichiers
//     PEM de spec/vecteurs/ct-6/<étiquette> (certificat ou clé privée
//     PKCS#8), public_key et address nuls, algorithme égal au type de la
//     clé (EX-A.7, révision 0.2). La clé publique est lue dans la structure,
//     sans les bornes de CT-6 EX-9.23 : une clé privée RSA est lue dans sa
//     structure RSAPrivateKey (RFC 8017 A.1.2), dont on tire n et e, puis le
//     SubjectPublicKeyInfo rsaEncryption à paramètres NULL est construit ;
//     crypto/x509 refuserait l'exposant 2³¹ + 1 de tsa-exposant.cle.pem.
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
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// Identifiants d'algorithme de clé publique (RFC 8017 A.1, RFC 5480 §2.1.1
// et §2.1.1.1, RFC 8410 §3).
var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256          = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// identifiantAlgorithme est l'AlgorithmIdentifier de RFC 5280 §4.1.1.2.
type identifiantAlgorithme struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// elementsDe rend les éléments d'une SEQUENCE DER, sans les décoder.
func elementsDe(der []byte) ([]asn1.RawValue, error) {
	var seq asn1.RawValue
	reste, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return nil, err
	}
	if len(reste) != 0 {
		return nil, errors.New("octets après la SEQUENCE")
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("SEQUENCE attendue")
	}
	var elements []asn1.RawValue
	for b := seq.Bytes; len(b) > 0; {
		var e asn1.RawValue
		r, err := asn1.Unmarshal(b, &e)
		if err != nil {
			return nil, err
		}
		elements = append(elements, e)
		b = r
	}
	return elements, nil
}

// entierPositif décode un INTEGER DER strictement positif.
func entierPositif(e asn1.RawValue, nom string) (*big.Int, error) {
	n := new(big.Int)
	if r, err := asn1.Unmarshal(e.FullBytes, &n); err != nil || len(r) != 0 {
		return nil, fmt.Errorf("%s : INTEGER illisible", nom)
	}
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("%s : non positif", nom)
	}
	return n, nil
}

// spkiRSA construit le SubjectPublicKeyInfo DER d'une clé RSA : algorithme
// rsaEncryption à paramètres NULL, clé RSAPublicKey ::= SEQUENCE { n, e }
// en BIT STRING (RFC 8017 A.1.1, RFC 5280 §4.1.2.7).
func spkiRSA(n, e *big.Int) ([]byte, error) {
	cle, err := asn1.Marshal(struct{ N, E *big.Int }{n, e})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		Algorithme identifiantAlgorithme
		Cle        asn1.BitString
	}{identifiantAlgorithme{oidRSAEncryption, asn1.NullRawValue}, asn1.BitString{Bytes: cle, BitLength: 8 * len(cle)}})
}

// spkiDeClePriveeRSA lit RSAPrivateKey ::= SEQUENCE { version, modulus n,
// publicExponent e, ... } (RFC 8017 A.1.2) et construit le
// SubjectPublicKeyInfo de n et e, sans borne sur la taille ni l'exposant.
func spkiDeClePriveeRSA(der []byte) ([]byte, error) {
	el, err := elementsDe(der)
	if err != nil {
		return nil, fmt.Errorf("RSAPrivateKey : %v", err)
	}
	if len(el) < 3 {
		return nil, fmt.Errorf("RSAPrivateKey de %d champs", len(el))
	}
	n, err := entierPositif(el[1], "modulus")
	if err != nil {
		return nil, err
	}
	e, err := entierPositif(el[2], "publicExponent")
	if err != nil {
		return nil, err
	}
	return spkiRSA(n, e)
}

// spkiDePKCS8 rend le SubjectPublicKeyInfo d'une clé privée PKCS#8
// (PrivateKeyInfo ::= SEQUENCE { version, privateKeyAlgorithm, privateKey
// OCTET STRING, ... }, RFC 5208 §5) : rsaEncryption est lu dans
// RSAPrivateKey ; tout autre algorithme (Ed25519 de RFC 8410, ECDSA) par
// crypto/x509, qui n'y applique pas de borne d'exposant.
func spkiDePKCS8(der []byte) ([]byte, error) {
	el, err := elementsDe(der)
	if err != nil {
		return nil, fmt.Errorf("PrivateKeyInfo : %v", err)
	}
	if len(el) < 3 {
		return nil, fmt.Errorf("PrivateKeyInfo de %d champs", len(el))
	}
	var algo identifiantAlgorithme
	if r, err := asn1.Unmarshal(el[1].FullBytes, &algo); err != nil || len(r) != 0 {
		return nil, errors.New("PrivateKeyInfo : privateKeyAlgorithm illisible")
	}
	if algo.Algorithm.Equal(oidRSAEncryption) {
		var cle []byte
		if r, err := asn1.Unmarshal(el[2].FullBytes, &cle); err != nil || len(r) != 0 {
			return nil, errors.New("PrivateKeyInfo : privateKey n'est pas un OCTET STRING")
		}
		return spkiDeClePriveeRSA(cle)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("clé sans partie publique")
	}
	return x509.MarshalPKIXPublicKey(s.Public())
}

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
		s, err := spkiDePKCS8(bloc.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s : %v", chemin, err)
		}
		return s, nil
	}
	return nil, fmt.Errorf("%s : bloc PEM %q non pris en charge", chemin, bloc.Type)
}

// algorithmeDeSPKI rend la valeur d'`algorithm` d'EX-A.7 pour le type de la
// clé d'un SubjectPublicKeyInfo : rsa, ecdsa_p256 ou ed25519.
func algorithmeDeSPKI(spki []byte) string {
	el, err := elementsDe(spki)
	if err != nil || len(el) != 2 {
		return "SubjectPublicKeyInfo illisible"
	}
	var algo identifiantAlgorithme
	if r, err := asn1.Unmarshal(el[0].FullBytes, &algo); err != nil || len(r) != 0 {
		return "AlgorithmIdentifier illisible"
	}
	switch {
	case algo.Algorithm.Equal(oidRSAEncryption):
		return "rsa"
	case algo.Algorithm.Equal(oidEd25519):
		return "ed25519"
	case algo.Algorithm.Equal(oidECPublicKey):
		var courbe asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(algo.Parameters.FullBytes, &courbe); err == nil && courbe.Equal(oidP256) {
			return "ecdsa_p256"
		}
		return "courbe elliptique autre que P-256"
	}
	return "algorithme " + algo.Algorithm.String()
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
		case src == "ct-6":
			// EX-A.7 : même forme pour rsa, ecdsa_p256 et ed25519.
			spki, err := spkiDePEM(filepath.Join(racine, "..", "ct-6", filepath.FromSlash(label)))
			if err != nil {
				rap.Erreur("%s : %v", vec, err)
				continue
			}
			rap.Comparer(fam, vec, "algorithme selon le type de la clé", algo, algorithmeDeSPKI(spki))
			rap.Constater(fam, vec, "public_key et address nuls (seule forme : spki_sha256)", k.Get("public_key").EstNull() && k.Get("address").EstNull(), "public_key ou address non nul")
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
