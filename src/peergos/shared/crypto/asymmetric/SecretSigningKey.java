package peergos.shared.crypto.asymmetric;

import jsinterop.annotations.JsType;
import peergos.shared.cbor.*;
import peergos.shared.crypto.asymmetric.curve25519.*;
import peergos.shared.crypto.hash.*;
import peergos.shared.crypto.random.*;
import peergos.shared.crypto.symmetric.*;
import peergos.shared.user.*;
import peergos.shared.util.*;

import java.io.*;
import java.util.*;
@JsType
public interface SecretSigningKey extends Cborable {

    PublicSigningKey.Type type();

    /**
     *
     * @param message
     * @return The signature + message
     */
    byte[] signMessage(byte[] message);

    /**
     *
     * @param message
     * @return Only the signature, excluding the original message
     */
    byte[] signatureOnly(byte[] message);

    @SuppressWarnings("unusable-by-js")
    static SecretSigningKey fromCbor(Cborable cbor) {
        if (! (cbor instanceof CborObject.CborList))
            throw new IllegalStateException("Invalid cbor for SecretSigningKey! " + cbor);
        CborObject.CborLong type = (CborObject.CborLong) ((CborObject.CborList) cbor).value.get(0);
        PublicSigningKey.Type t = PublicSigningKey.Type.byValue((int) type.value);
        switch (t) {
            case Ed25519:
                return Ed25519SecretKey.fromCbor(cbor, PublicSigningKey.PROVIDERS.get(t));
            default: throw new IllegalStateException("Unknown Secret Signing Key type: "+t.name());
        }
    }
}