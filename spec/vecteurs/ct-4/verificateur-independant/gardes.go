// Gardes de la revue de sécurité de l'étape 8 : accès aux valeurs qui
// tolèrent une entrée absente (nil), et protection commune des familles
// (une panne devient une erreur consignée, jamais une trace de pile).

package main

// nombreDe rend le littéral d'une valeur nombre, "" pour une valeur absente
// ou d'un autre type.
func nombreDe(v *Value) string {
	if v == nil || v.Kind != KindNumber {
		return ""
	}
	return v.Num
}
