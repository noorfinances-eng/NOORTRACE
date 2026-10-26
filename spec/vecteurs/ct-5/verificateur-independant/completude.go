// Complétude au registre (CT-5 AN-61, EX-10.7) : contrôle de série hors
// dossier. Toute ancre Anchored de docType point de contrôle émise par une clé
// de chaîne de l'enregistreur dans la fenêtre ]de_bloc, a_bloc] DOIT avoir
// pour empreinte keccak256(org_id ‖ journal_id ‖ checkpointHash) d'un point
// publié de l'une des séries servies (une série : les points d'une période
// d'un journal) ; l'ordre des blocs DOIT suivre celui des checkpoint_ts d'une
// même série.

package main

import (
	"sort"
	"strings"
)

// AncreCapturee est un événement Anchored capturé.
type AncreCapturee struct {
	Fingerprint string
	DocType     string
	BlockNumber int64
	LogIndex    int64
	Issuer      string
}

// PointPublie est un point de la série publiée d'un journal.
type PointPublie struct {
	CheckpointHash string
	CheckpointTs   string
}

// JournalPublie est la série publiée d'une période d'un journal.
type JournalPublie struct {
	OrgID, JournalID string
	Points           []PointPublie
}

// ResultatCompletude est le résultat du contrôle.
type ResultatCompletude struct {
	Complet    bool
	Orphelines []string
	HorsOrdre  []string
	Rattachees int
}

// VerifierCompletude applique AN-61.
func VerifierCompletude(journaux []JournalPublie, ancres []AncreCapturee, emetteurs []string, deBloc, aBloc int64) (*ResultatCompletude, error) {
	type rattache struct {
		serie int
		ts    int64
	}
	index := map[string]rattache{}
	for serie, j := range journaux {
		for _, p := range j.Points {
			ts, err := Ms(p.CheckpointTs)
			if err != nil {
				return nil, err
			}
			index[strings.ToLower(EmpreinteAncre(j.OrgID, j.JournalID, p.CheckpointHash))] = rattache{serie: serie, ts: ts}
		}
	}
	emet := map[string]bool{}
	for _, e := range emetteurs {
		emet[strings.ToLower(e)] = true
	}
	var vues []AncreCapturee
	for _, a := range ancres {
		if strings.ToLower(a.DocType) == DocTypePointDeControle && emet[strings.ToLower(a.Issuer)] && a.BlockNumber > deBloc && a.BlockNumber <= aBloc {
			vues = append(vues, a)
		}
	}
	sort.SliceStable(vues, func(i, j int) bool {
		if vues[i].BlockNumber != vues[j].BlockNumber {
			return vues[i].BlockNumber < vues[j].BlockNumber
		}
		return vues[i].LogIndex < vues[j].LogIndex
	})
	r := &ResultatCompletude{Orphelines: []string{}, HorsOrdre: []string{}}
	dernier := map[int]int64{}
	for _, a := range vues {
		x, ok := index[strings.ToLower(a.Fingerprint)]
		if !ok {
			r.Orphelines = append(r.Orphelines, a.Fingerprint)
			continue
		}
		r.Rattachees++
		if prec, ok := dernier[x.serie]; ok && x.ts < prec {
			r.HorsOrdre = append(r.HorsOrdre, a.Fingerprint)
		}
		dernier[x.serie] = x.ts
	}
	r.Complet = len(r.Orphelines) == 0 && len(r.HorsOrdre) == 0
	return r, nil
}
