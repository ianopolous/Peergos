package peergos.shared.crypto;

import peergos.shared.cbor.*;
import peergos.shared.crypto.asymmetric.*;
import peergos.shared.crypto.asymmetric.curve25519.*;
import peergos.shared.crypto.random.*;

import java.util.*;

public class BoxingKeyPair implements Cborable
{
    public final PublicBoxingKey publicBoxingKey;
    public final SecretBoxingKey secretBoxingKey;

    public BoxingKeyPair(PublicBoxingKey publicBoxingKey, SecretBoxingKey secretBoxingKey) {
        this.publicBoxingKey = publicBoxingKey;
        this.secretBoxingKey = secretBoxingKey;
    }

    @Override
    public CborObject toCbor() {
        return new CborObject.CborList(Arrays.asList(
                publicBoxingKey.toCbor(),
                secretBoxingKey.toCbor()));
    }

    public static BoxingKeyPair fromCbor(Cborable cbor) {
        if (! (cbor instanceof CborObject.CborList))
            throw new IllegalStateException("Incorrect cbor for SigningKeyPair: " + cbor);

        List<? extends Cborable> values = ((CborObject.CborList) cbor).value;
        PublicBoxingKey pub = PublicBoxingKey.fromCbor(values.get(0));
        SecretBoxingKey secret = SecretBoxingKey.fromCbor(values.get(1));
        return new BoxingKeyPair(pub, secret);
    }

    public static BoxingKeyPair random(SafeRandom random, Curve25519 boxer) {

        byte[] secretBoxBytes = new byte[32];
        byte[] publicBoxBytes = new byte[32];

        random.randombytes(secretBoxBytes, 0, 32);

        return random(secretBoxBytes, publicBoxBytes, boxer, random);
    }

    private static BoxingKeyPair random(byte[] secretBoxBytes, byte[] publicBoxBytes,
                                        Curve25519 boxer, SafeRandom random) {
        boxer.crypto_box_keypair(publicBoxBytes, secretBoxBytes);

        return new BoxingKeyPair(
                new Curve25519PublicKey(publicBoxBytes, boxer, random),
                new Curve25519SecretKey(secretBoxBytes, boxer));
    }
}
