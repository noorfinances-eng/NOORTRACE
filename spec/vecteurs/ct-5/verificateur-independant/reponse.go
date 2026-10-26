// Classement d'une réponse RFC 3161 reçue (CT-5 EX-5.10 à EX-5.12, AN-8 à
// AN-11) et attente de reprise (EX-8.9). Les vérifications T-1 à T-9 de
// CT-6 sont des résultats déclarés (checks_passed) : ce module ne refait ni
// la signature ni le chemin de certification (EX-A.4).

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// TypesContenuReponse sont les types de contenu admis (EX-5.5).
var TypesContenuReponse = []string{"application/timestamp-reply", "application/timestamp-response"}

var httpTransitoires = map[int64]bool{408: true, 429: true, 500: true, 502: true, 503: true, 504: true}
var echecsTransitoires = map[string]bool{"timeNotAvailable": true, "systemFailure": true}

// HTTP décrit la réponse de transport (EX-5.5).
type HTTP struct {
	Status      *int64
	ContentType *string
	BodySize    *int64
	RetryAfterS *int64
}

// Fraicheur est la section freshness de la configuration.
type Fraicheur struct {
	MaxResponseDelayS int64
	ClockToleranceS   int64
}

// Reprise est la section retry de la configuration.
type Reprise struct {
	InitialMs float64
	Factor    float64
	MaxMs     float64
	JitterMs  int64
}

// Evaluation est le résultat du classement d'EX-5.10.
type Evaluation struct {
	Outcome         string
	ErrorCode       *string
	Class           *string
	Critical        bool
	Warnings        []string
	HTTPStatus      int64
	PKIStatus       *int64
	FailureInfo     *string
	NonceInResponse *string
	ImprintMatches  *bool
	Token           []byte
	TokenSHA256     *string
	TokenSize       *int64
	GenTime         *string
	AccuracyS       *float64
	UpperBound      *string
	Detail          string
}

func ptrS(s string) *string { return &s }
func ptrI(n int64) *int64   { return &n }
func ptrB(b bool) *bool     { return &b }

// SHA256Hex rend le SHA-256 en 0x.
func SHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return "0x" + hex.EncodeToString(s[:])
}

// EvaluerReponse classe une réponse : requete (octets envoyés), reponse
// (corps reçu, nil si aucun), http, instants d'envoi et de réception,
// politiques admises du prestataire (nil : toutes), fraîcheur, nombre de
// réponses tardives consécutives déjà reçues, vérifications T- déclarées.
func EvaluerReponse(requete, reponse []byte, http HTTP, sentAt, receivedAt string, acceptedPolicies []string, fr Fraicheur, tardivesPrecedentes int64, checksPassed map[string]bool) (*Evaluation, error) {
	req, err := LireRequete(requete)
	if err != nil {
		return nil, err
	}
	res := &Evaluation{Outcome: "echec_permanente", Class: ptrS("permanente"), Warnings: []string{}, HTTPStatus: 200}
	if http.Status != nil {
		res.HTTPStatus = *http.Status
	}
	echec := func(code, classe, detail string) *Evaluation {
		r := *res
		r.ErrorCode = ptrS(code)
		r.Class = ptrS(classe)
		r.Detail = detail
		if classe == "transitoire" {
			r.Outcome = "echec_transitoire"
		} else {
			r.Outcome = "echec_permanente"
		}
		return &r
	}
	// 1. transport
	if res.HTTPStatus != 200 {
		classe := "permanente"
		if httpTransitoires[res.HTTPStatus] {
			classe = "transitoire"
		}
		detail := fmt.Sprintf("http %d", res.HTTPStatus)
		if http.RetryAfterS != nil {
			detail += fmt.Sprintf(" ; Retry-After %d s", *http.RetryAfterS)
		}
		return echec(fmt.Sprintf("http_%d", res.HTTPStatus), classe, detail), nil
	}
	typ := TypesContenuReponse[0]
	if http.ContentType != nil {
		typ = *http.ContentType
	}
	base := strings.ToLower(strings.TrimSpace(strings.SplitN(typ, ";", 2)[0]))
	admis := false
	for _, t := range TypesContenuReponse {
		if t == base {
			admis = true
		}
	}
	if !admis {
		return echec("type_contenu", "permanente", "Content-Type "+typ+" non admis"), nil
	}
	taille := int64(len(reponse))
	if http.BodySize != nil {
		taille = *http.BodySize
	}
	if taille > TailleMaxReponse {
		return echec("taille", "permanente", fmt.Sprintf("corps de %d octets, au plus %d", taille, TailleMaxReponse)), nil
	}
	// 2. TimeStampResp
	rep, err := LireReponseTsa(reponse)
	if err != nil {
		return echec("reponse_illisible", "permanente", err.Error()), nil
	}
	res.PKIStatus = ptrI(rep.Status)
	res.FailureInfo = rep.FailInfo
	switch rep.Status {
	case 2:
		if rep.FailInfo == nil {
			return echec("statut_2", "permanente", "PKIStatus 2 (rejection) sans PKIFailureInfo"), nil
		}
		classe := "permanente"
		if echecsTransitoires[*rep.FailInfo] {
			classe = "transitoire"
		}
		return echec("echec_"+*rep.FailInfo, classe, "PKIStatus 2 (rejection) ; "+*rep.FailInfo), nil
	case 3:
		return echec("statut_3", "transitoire", "PKIStatus 3 (waiting)"), nil
	case 4, 5:
		r := echec(fmt.Sprintf("statut_%d", rep.Status), "permanente", fmt.Sprintf("PKIStatus %d (%s)", rep.Status, NomsPKI[rep.Status]))
		r.Critical = true
		return r, nil
	}
	if rep.Token == nil {
		return echec("reponse_illisible", "permanente", fmt.Sprintf("PKIStatus %d sans TimeStampToken", rep.Status)), nil
	}
	res.Token = rep.Token
	res.TokenSHA256 = ptrS(SHA256Hex(rep.Token))
	res.TokenSize = ptrI(int64(len(rep.Token)))
	// 3 à 6. jeton
	tst, err := LireJetonTST(rep.Token)
	if err != nil {
		return echec("verification_T-1", "permanente", "jeton inexploitable (T-1)"), nil
	}
	imprint := len(tst.Empreinte) == 32 && "0x"+hex.EncodeToString(tst.Empreinte) == req.Digest && tst.EmpreinteAlgo == OIDSHA256
	res.ImprintMatches = ptrB(imprint)
	if tst.Nonce != nil {
		res.NonceInResponse = ptrS(HexNonce(tst.Nonce))
	}
	genTime := LireGenTime(tst.GenTimeTexte)
	var acc float64
	if genTime != nil {
		res.GenTime = ptrS(genTime.RFC3339())
		if tst.Precision != nil {
			acc = tst.Precision.Secondes()
			res.AccuracyS = &acc
		}
		res.UpperBound = ptrS(Iso(genTime.Ms() + int64(math.Round(acc*1000))))
	}
	if !imprint {
		return echec("empreinte_differente", "permanente", "messageImprint different de l'empreinte demandee"), nil
	}
	if tst.Nonce == nil {
		return echec("nonce_absent", "permanente", "nonce absent du TSTInfo"), nil
	}
	if tst.Nonce.Cmp(req.Nonce) != 0 {
		return echec("nonce_different", "permanente", fmt.Sprintf("nonce %s different de %s", *res.NonceInResponse, HexNonce(req.Nonce))), nil
	}
	if req.PolicyOID != nil && tst.Politique != *req.PolicyOID {
		return echec("politique_differente", "permanente", fmt.Sprintf("politique %s differente de la politique demandee %s", tst.Politique, *req.PolicyOID)), nil
	}
	if acceptedPolicies != nil {
		ok := false
		for _, p := range acceptedPolicies {
			if p == tst.Politique {
				ok = true
			}
		}
		if !ok {
			return echec("politique_refusee", "permanente", fmt.Sprintf("politique %s hors de accepted_policies", tst.Politique)), nil
		}
	}
	for i := 1; i <= 9; i++ {
		id := fmt.Sprintf("T-%d", i)
		if !checksPassed[id] {
			return echec("verification_"+id, "permanente", fmt.Sprintf("verification %s en echec ou absente", id)), nil
		}
	}
	// 7 et 8. fraîcheur et horloge
	envoi, err := Ms(sentAt)
	if err != nil {
		return nil, err
	}
	reception, err := Ms(receivedAt)
	if err != nil {
		return nil, err
	}
	if genTime == nil {
		return echec("verification_T-9", "permanente", "genTime illisible"), nil
	}
	genMs := genTime.Ms()
	if reception-envoi > fr.MaxResponseDelayS*1000 {
		if tardivesPrecedentes+1 < 3 {
			r := *res
			r.Outcome = "reponse_tardive"
			r.ErrorCode = ptrS("reponse_tardive")
			r.Class = ptrS("transitoire")
			r.Detail = fmt.Sprintf("reponse recue %d s apres l'envoi", (reception-envoi)/1000)
			return &r, nil
		}
		res.Warnings = append(res.Warnings, "reponse_tardive")
	}
	if d := genMs - envoi; d > fr.ClockToleranceS*1000 || -d > fr.ClockToleranceS*1000 {
		res.Warnings = append(res.Warnings, "horloge_suspecte")
	}
	res.Outcome = "obtenue"
	res.ErrorCode = nil
	res.Class = nil
	res.Detail = NomsPKI[rep.Status] + " ; T-1 a T-9 reussies"
	if len(res.Warnings) > 0 {
		res.Detail += " ; avertissement " + strings.Join(res.Warnings, ", ")
	}
	return res, nil
}

// CalculerAttente rend l'attente de reprise d'EX-8.9 : k est le rang de
// l'échec transitoire consécutif (1 pour le premier), premier408Servi dit si
// le rejeu immédiat du premier 408 a déjà eu lieu, gigue un entier de
// [0, jitter_ms]. Rend (délai en millisecondes, raison).
func CalculerAttente(httpStatus *int64, retryAfterS *int64, k int64, premier408Servi bool, retry Reprise, gigue int64) (float64, string) {
	if httpStatus != nil && (*httpStatus == 429 || *httpStatus == 503) && retryAfterS != nil {
		return float64(*retryAfterS) * 1000, "retry_after"
	}
	if httpStatus != nil && *httpStatus == 408 && !premier408Servi {
		return 0, "immediat"
	}
	base := math.Min(retry.MaxMs, retry.InitialMs*math.Pow(retry.Factor, float64(k-1)))
	return base + float64(gigue), "backoff"
}
