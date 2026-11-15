package schema

// Essai de la revue de sécurité interne de l'étape 8 : uniqueItems en
// temps linéaire.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

// TestUniqueItemsLineaire : uniqueItems en temps linéaire. Un tableau de 65 535 chaînes distinctes
// (la borne des schémas de CT-1) est validé en moins de deux secondes ; la
// comparaison de chaque couple prenait vingt secondes et plus. Un doublon
// est encore trouvé, aux rangs qu'il occupe, y compris entre objets dont
// l'ordre des membres diffère.
func TestUniqueItemsLineaire(t *testing.T) {
	s, err := jsonv.Analyser([]byte(`{"type":"array","uniqueItems":true}`))
	if err != nil {
		t.Fatal(err)
	}
	v := &validateur{}
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 65535; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"0x%040x"`, i+1)
	}
	sb.WriteString("]")
	x, err := jsonv.Analyser([]byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	debut := time.Now()
	if err := v.tableau(s, x, "", 0); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(debut); d > 2*time.Second {
		t.Fatalf("uniqueItems sur 65 535 éléments : %s, seuil 2 s", d)
	}
	// Doublon : le dernier élément répète le premier.
	x.Elements[65534] = x.Elements[0]
	err = v.tableau(s, x, "", 0)
	if err == nil || !strings.Contains(err.Error(), "éléments 0 et 65534 identiques") {
		t.Fatalf("doublon non trouvé : %v", err)
	}
	y, _ := jsonv.Analyser([]byte(`[{"a":1,"b":2},{"c":3},{"b":2,"a":1}]`))
	err = v.tableau(s, y, "", 0)
	if err == nil || !strings.Contains(err.Error(), "éléments 0 et 2 identiques") {
		t.Fatalf("objets égaux à l'ordre près : %v", err)
	}
}
