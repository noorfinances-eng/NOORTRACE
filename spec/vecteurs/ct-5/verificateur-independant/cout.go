// Comptages (CT-5 EX-4.11) et formule de coût (section 12, EX-12.1,
// EX-12.2) : les prix sont des paramètres symboliques du cas, jamais une
// valeur de ce module.

package main

import "math"

// CasCout est l'entrée d'un cas `$defs/cas_cout`.
type CasCout struct {
	Journals                  int64
	HoursPerYear              int64
	CheckpointIntervalS       int64
	Rfc3161CheckpointInterval int64
	ActivityRatio             float64
	ProviderRole              string
	CountersignIdle           bool
	RegistryCheckpoints       string
	UnitPriceQualified        float64
	UnitPriceSecondRank       float64
	SubscriptionFee           float64
	SubscriptionQuota         *float64
	BillableRetryRatio        float64
}

// ResultatCout rend les six grandeurs attendues, arrondies à trois décimales.
type ResultatCout struct {
	QualifiedTokensPerJournal  float64
	SecondRankTokensPerJournal float64
	RegistryAnchorsPerJournal  float64
	GasUpperBoundPerJournal    float64
	CostPerJournal             float64
	CostTotal                  float64
}

func arrondi3(x float64) float64 { return math.Round(x*1000) / 1000 }

// Cout applique la formule de la section 12 (AN-59).
func Cout(i CasCout) (*ResultatCout, error) {
	for nom, v := range map[string]int64{"hours_per_year": i.HoursPerYear, "journals": i.Journals, "rfc3161_checkpoint_interval_s": i.Rfc3161CheckpointInterval, "checkpoint_interval_s": i.CheckpointIntervalS} {
		if v <= 0 {
			return nil, refus("AN-59", "%s : entier > 0 attendu", nom)
		}
	}
	if 3600%i.Rfc3161CheckpointInterval != 0 || 3600%i.CheckpointIntervalS != 0 {
		return nil, refus("AN-59", "cadences : diviseurs de 3600 attendus")
	}
	a := i.ActivityRatio
	if i.CountersignIdle {
		a = 1
	}
	if !(a >= 0 && a <= 1) {
		return nil, refus("AN-59", "activity_ratio : nombre de [0, 1] attendu")
	}
	H := float64(i.HoursPerYear)
	nT := float64(3600 / i.Rfc3161CheckpointInterval)
	points := (nT - 1) * a
	if i.ProviderRole == "aucun" {
		points = 0
	}
	Nq := H
	if i.ProviderRole == "principal" {
		Nq = H * (1 + points)
	}
	Ns := 0.0
	if i.ProviderRole == "second_rang" || i.ProviderRole == "interne" {
		Ns = H * points
	}
	Na := H
	if i.RegistryCheckpoints != "aucun" {
		// EX-12.1 : points aux instants period_start + j × c_K et point de clôture, plus le manifeste.
		Na = H * (2 + float64(3600/i.CheckpointIntervalS))
	}
	G := Na*96977 + H*314256
	r := i.BillableRetryRatio
	bq := Nq * (1 + r)
	bs := Ns * (1 + r)
	var C float64
	if i.SubscriptionFee == 0 {
		C = i.UnitPriceQualified*bq + i.UnitPriceSecondRank*bs
	} else {
		depassement := 0.0
		if i.SubscriptionQuota != nil {
			depassement = math.Max(0, bq-*i.SubscriptionQuota)
		}
		C = i.SubscriptionFee + i.UnitPriceQualified*depassement + i.UnitPriceSecondRank*bs
	}
	return &ResultatCout{
		QualifiedTokensPerJournal:  arrondi3(Nq),
		SecondRankTokensPerJournal: arrondi3(Ns),
		RegistryAnchorsPerJournal:  arrondi3(Na),
		GasUpperBoundPerJournal:    arrondi3(G),
		CostPerJournal:             arrondi3(C),
		CostTotal:                  arrondi3(float64(i.Journals) * C),
	}, nil
}

// Comptages par heure (EX-4.11, AN-4) d'une projection de configuration.
type Comptages struct {
	NT                 int64
	DeadlinesPerHour   int64
	Tokens             int64
	QualifiedTokens    int64
	CheckpointTokens   int64
	RegistryAnchorsMax int64
	OtsSubmissions     int64
}

// CompterJetons rend les comptages par heure d'une projection (EX-4.11).
func CompterJetons(c *Config) (*Comptages, error) {
	cT := c.CheckpointsIntervalS
	cK := c.CheckpointIntervalS
	if cT < 60 || cT > 3600 || 3600%cT != 0 {
		return nil, refus("AN-1", "interval_s %d : diviseur de 3600 entre 60 et 3600 attendu", cT)
	}
	if cK < 1 || 3600%cK != 0 {
		return nil, refus("AN-1", "checkpoint_interval_s %d : diviseur de 3600 attendu", cK)
	}
	nT := 3600 / cT
	points := nT - 1
	if c.ProviderRole == "aucun" {
		points = 0
	}
	r := &Comptages{NT: nT, DeadlinesPerHour: nT - 1, Tokens: 1 + points, QualifiedTokens: 1, CheckpointTokens: points, RegistryAnchorsMax: 1}
	if c.ProviderRole == "principal" {
		r.QualifiedTokens += points
	}
	if c.RegistryCheckpoints != "aucun" {
		r.RegistryAnchorsMax += 1 + 3600/cK // EX-4.11 : points alignés et point de clôture
	}
	if c.OtsEnabled {
		r.OtsSubmissions = 1
		if c.OtsCheckpoint == "mi_periode" {
			r.OtsSubmissions = 2
		}
	}
	return r, nil
}
