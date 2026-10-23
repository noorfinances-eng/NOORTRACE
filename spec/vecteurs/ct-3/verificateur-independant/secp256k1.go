// Courbe secp256k1 (SEC 2 §2.4.1), écrite ici en math/big : la
// bibliothèque standard de Go n'en a pas (crypto/ecdsa ne couvre que les
// courbes NIST), et le module reste sans dépendance (CT-3 EX-A.10).
//
// Fonctions : multiplication scalaire (clé publique d'une clé privée),
// recouvrement de la clé publique d'une signature ECDSA (SEC 1 §4.1.6), et,
// pour les tests et la reproduction des signatures des vecteurs, signature
// ECDSA déterministe (RFC 6979 §3.2, HMAC-SHA-256). Les points sont tenus en
// coordonnées jacobiennes ; rien ici n'est à temps constant : ce module ne
// manipule que des clés de test publiques.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
)

var (
	secpP, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secpN, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secpGx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secpGy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	// secpDemiN est ⌊n/2⌋ : un s de la moitié basse vérifie s ≤ ⌊n/2⌋
	// (CT-1 §6.3 et E-9, CT-3 EX-9.3).
	secpDemiN = new(big.Int).Rsh(secpN, 1)
	secpSept  = big.NewInt(7)
)

// pointJ est un point en coordonnées jacobiennes (X/Z², Y/Z³) ; Z = 0 est le
// point à l'infini.
type pointJ struct{ X, Y, Z *big.Int }

func infini() pointJ { return pointJ{new(big.Int), new(big.Int), new(big.Int)} }

func (q pointJ) estInfini() bool { return q.Z.Sign() == 0 }

func modP(x *big.Int) *big.Int { return x.Mod(x, secpP) }

func jacobien(x, y *big.Int) pointJ {
	return pointJ{new(big.Int).Set(x), new(big.Int).Set(y), big.NewInt(1)}
}

// doubler rend 2·q (formules « dbl-2009-l », a = 0).
func doubler(q pointJ) pointJ {
	if q.estInfini() || q.Y.Sign() == 0 {
		return infini()
	}
	a := modP(new(big.Int).Mul(q.X, q.X))
	b := modP(new(big.Int).Mul(q.Y, q.Y))
	c := modP(new(big.Int).Mul(b, b))
	t := new(big.Int).Add(q.X, b)
	t.Mul(t, t)
	t.Sub(t, a)
	t.Sub(t, c)
	d := modP(t.Lsh(t, 1))
	e := modP(new(big.Int).Mul(a, big.NewInt(3)))
	f := modP(new(big.Int).Mul(e, e))
	x3 := modP(new(big.Int).Sub(f, new(big.Int).Lsh(d, 1)))
	y3 := new(big.Int).Sub(d, x3)
	y3.Mul(y3, e)
	y3.Sub(y3, new(big.Int).Lsh(c, 3))
	modP(y3)
	z3 := new(big.Int).Mul(q.Y, q.Z)
	modP(z3.Lsh(z3, 1))
	return pointJ{x3, y3, z3}
}

// additionner rend q1 + q2 (formules « add-2007-bl »).
func additionner(q1, q2 pointJ) pointJ {
	if q1.estInfini() {
		return q2
	}
	if q2.estInfini() {
		return q1
	}
	z1z1 := modP(new(big.Int).Mul(q1.Z, q1.Z))
	z2z2 := modP(new(big.Int).Mul(q2.Z, q2.Z))
	u1 := modP(new(big.Int).Mul(q1.X, z2z2))
	u2 := modP(new(big.Int).Mul(q2.X, z1z1))
	s1 := modP(new(big.Int).Mul(new(big.Int).Mul(q1.Y, q2.Z), z2z2))
	s2 := modP(new(big.Int).Mul(new(big.Int).Mul(q2.Y, q1.Z), z1z1))
	h := modP(new(big.Int).Sub(u2, u1))
	rr := modP(new(big.Int).Sub(s2, s1))
	if h.Sign() == 0 {
		if rr.Sign() == 0 {
			return doubler(q1)
		}
		return infini()
	}
	rr.Lsh(rr, 1)
	modP(rr)
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	modP(i)
	j := modP(new(big.Int).Mul(h, i))
	v := modP(new(big.Int).Mul(u1, i))
	x3 := new(big.Int).Mul(rr, rr)
	x3.Sub(x3, j)
	x3.Sub(x3, new(big.Int).Lsh(v, 1))
	modP(x3)
	y3 := new(big.Int).Sub(v, x3)
	y3.Mul(y3, rr)
	y3.Sub(y3, new(big.Int).Lsh(new(big.Int).Mul(s1, j), 1))
	modP(y3)
	z3 := new(big.Int).Add(q1.Z, q2.Z)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	modP(z3)
	return pointJ{x3, y3, z3}
}

// multiplier rend k·q (double-et-additionne, bits de poids fort d'abord).
func multiplier(k *big.Int, q pointJ) pointJ {
	r := infini()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = doubler(r)
		if k.Bit(i) == 1 {
			r = additionner(r, q)
		}
	}
	return r
}

// affine rend les coordonnées affines d'un point fini.
func affine(q pointJ) (*big.Int, *big.Int) {
	zi := new(big.Int).ModInverse(q.Z, secpP)
	zi2 := modP(new(big.Int).Mul(zi, zi))
	x := modP(new(big.Int).Mul(q.X, zi2))
	y := modP(new(big.Int).Mul(q.Y, modP(new(big.Int).Mul(zi2, zi))))
	return x, y
}

func generateur() pointJ { return jacobien(secpGx, secpGy) }

// surLaCourbe dit si (x, y) vérifie y² = x³ + 7 (mod p).
func surLaCourbe(x, y *big.Int) bool {
	g := modP(new(big.Int).Mul(y, y))
	d := new(big.Int).Exp(x, big.NewInt(3), secpP)
	d.Add(d, secpSept)
	modP(d)
	return g.Cmp(d) == 0
}

// ClePublique rend la clé publique non compressée (64 octets X ‖ Y) d'une
// clé privée de 32 octets.
func ClePublique(prive []byte) ([]byte, error) {
	d := new(big.Int).SetBytes(prive)
	if d.Sign() == 0 || d.Cmp(secpN) >= 0 {
		return nil, errors.New("clé privée hors de [1, n-1]")
	}
	x, y := affine(multiplier(d, generateur()))
	return concat32(x, y), nil
}

// AdresseDeCle rend l'adresse Ethereum (20 octets) d'une clé publique non
// compressée de 64 octets : les 20 derniers octets de son keccak256.
func AdresseDeCle(pub []byte) []byte { return Keccak256(pub)[12:] }

// AdresseDePrivee rend l'adresse d'une clé privée.
func AdresseDePrivee(prive []byte) ([]byte, error) {
	pub, err := ClePublique(prive)
	if err != nil {
		return nil, err
	}
	return AdresseDeCle(pub), nil
}

func octets32(x *big.Int) []byte {
	b := make([]byte, 32)
	x.FillBytes(b)
	return b
}

func concat32(x, y *big.Int) []byte {
	return append(octets32(x), octets32(y)...)
}

// Recouvrer rend la clé publique (64 octets) dont la signature (r, s) sur le
// condensé h de 32 octets a l'indice de recouvrement recid ∈ {0, 1} (parité
// de y de R ; SEC 1 §4.1.6, sans le cas x = r + n, que v ∈ {27, 28} ne
// désigne pas). Les s des deux moitiés sont acceptés : la canonicité est
// contrôlée à part (EX-9.3, SG-5).
func Recouvrer(h []byte, r, s *big.Int, recid int) ([]byte, error) {
	if r.Sign() <= 0 || r.Cmp(secpN) >= 0 || s.Sign() <= 0 || s.Cmp(secpN) >= 0 {
		return nil, errors.New("r ou s hors de [1, n-1]")
	}
	if recid != 0 && recid != 1 {
		return nil, errors.New("indice de recouvrement hors de {0, 1}")
	}
	x := new(big.Int).Set(r)
	if x.Cmp(secpP) >= 0 {
		return nil, errors.New("x de R hors du corps")
	}
	c := new(big.Int).Exp(x, big.NewInt(3), secpP)
	c.Add(c, secpSept)
	modP(c)
	exp := new(big.Int).Add(secpP, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(c, exp, secpP)
	if modP(new(big.Int).Mul(y, y)).Cmp(c) != 0 {
		return nil, errors.New("r n'est l'abscisse d'aucun point de la courbe")
	}
	if int(y.Bit(0)) != recid {
		y.Sub(secpP, y)
	}
	e := new(big.Int).SetBytes(h)
	rInv := new(big.Int).ModInverse(r, secpN)
	u1 := new(big.Int).Neg(e)
	u1.Mul(u1, rInv)
	u1.Mod(u1, secpN)
	u2 := new(big.Int).Mul(s, rInv)
	u2.Mod(u2, secpN)
	q := additionner(multiplier(u1, generateur()), multiplier(u2, jacobien(x, y)))
	if q.estInfini() {
		return nil, errors.New("clé recouvrée à l'infini")
	}
	qx, qy := affine(q)
	if !surLaCourbe(qx, qy) {
		return nil, errors.New("clé recouvrée hors de la courbe")
	}
	return concat32(qx, qy), nil
}

// SignerDeterministe signe le condensé h (32 octets) par ECDSA avec un nonce
// RFC 6979 (HMAC-SHA-256) et rend (r, s, recid) avec s dans la moitié basse
// (recid ajusté en conséquence).
func SignerDeterministe(prive, h []byte) (*big.Int, *big.Int, int, error) {
	d := new(big.Int).SetBytes(prive)
	if d.Sign() == 0 || d.Cmp(secpN) >= 0 {
		return nil, nil, 0, errors.New("clé privée hors de [1, n-1]")
	}
	// RFC 6979 §3.2 : qlen = hlen = 256 ; bits2octets(h) = int(h) mod n.
	hm := new(big.Int).SetBytes(h)
	hm.Mod(hm, secpN)
	x := octets32(d)
	ho := octets32(hm)
	v := make([]byte, 32)
	for i := range v {
		v[i] = 0x01
	}
	k := make([]byte, 32)
	mac := func(cle []byte, morceaux ...[]byte) []byte {
		m := hmac.New(sha256.New, cle)
		for _, p := range morceaux {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	k = mac(k, v, []byte{0x00}, x, ho)
	v = mac(k, v)
	k = mac(k, v, []byte{0x01}, x, ho)
	v = mac(k, v)
	for {
		v = mac(k, v)
		kk := new(big.Int).SetBytes(v)
		if kk.Sign() > 0 && kk.Cmp(secpN) < 0 {
			rx, ry := affine(multiplier(kk, generateur()))
			r := new(big.Int).Mod(rx, secpN)
			if r.Sign() != 0 {
				kInv := new(big.Int).ModInverse(kk, secpN)
				s := new(big.Int).Mul(r, d)
				s.Add(s, new(big.Int).SetBytes(h))
				s.Mul(s, kInv)
				s.Mod(s, secpN)
				if s.Sign() != 0 {
					recid := int(ry.Bit(0))
					if rx.Cmp(secpN) >= 0 {
						recid |= 2
					}
					if s.Cmp(secpDemiN) > 0 {
						s.Sub(secpN, s)
						recid ^= 1
					}
					return r, s, recid, nil
				}
			}
		}
		k = mac(k, v, []byte{0x00})
		v = mac(k, v)
	}
}
