# Confrontation par la bibliothèque officielle (CT-5 annexe A.6, EX-6.3) :
# relit un fichier .ots (ou, avec « --timestamp <empreinte hex> », un
# Timestamp nu sur ce message) avec python-opentimestamps, exige la fin de
# fichier exacte, le resérialise et écrit les octets obtenus sur la sortie
# standard, précédés d'une ligne JSON de description. Lancé avec « python -I ».
import json
import sys

from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation


def principal(arguments):
    if len(arguments) >= 3 and arguments[0] == "--timestamp":
        message = bytes.fromhex(arguments[1])
        chemin = arguments[2]
        with open(chemin, "rb") as f:
            octets = f.read()
        ctx = BytesDeserializationContext(octets)
        timestamp = Timestamp.deserialize(ctx, message)
        ctx.assert_eof()
        sortie = BytesSerializationContext()
        timestamp.serialize(sortie)
        empreinte = message.hex()
    else:
        chemin = arguments[0]
        with open(chemin, "rb") as f:
            octets = f.read()
        ctx = BytesDeserializationContext(octets)
        fichier = DetachedTimestampFile.deserialize(ctx)
        ctx.assert_eof()
        sortie = BytesSerializationContext()
        fichier.serialize(sortie)
        timestamp = fichier.timestamp
        empreinte = fichier.file_digest.hex()
    attestations = []
    for message_attestation, attestation in timestamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            attestations.append({"kind": "bitcoin", "height": attestation.height})
        elif isinstance(attestation, PendingAttestation):
            attestations.append({"kind": "en_attente", "uri": attestation.uri})
        else:
            attestations.append({"kind": "inconnue"})
    reserialise = sortie.getbytes()
    description = {"digest": empreinte, "identical": reserialise == octets, "attestations": attestations, "size": len(reserialise)}
    sys.stdout.write(json.dumps(description, sort_keys=True) + "\n")
    sys.stdout.flush()
    sys.stdout.buffer.write(reserialise)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(principal(sys.argv[1:]))
