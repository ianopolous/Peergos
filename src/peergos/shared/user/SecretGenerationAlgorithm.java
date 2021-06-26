package peergos.shared.user;

import jsinterop.annotations.*;
import peergos.shared.cbor.*;
import peergos.shared.crypto.random.*;
import peergos.shared.util.*;

import java.util.*;

public interface SecretGenerationAlgorithm extends Cborable {
    Map<Integer, Type> byValue = new HashMap<>();
    @JsType
    enum Type {
        Random(0x0),
        Scrypt(0x1);

        public final int value;

        Type(int value) {
            this.value = value;
            byValue.put(value, this);
        }

        public static Type byValue(int val) {
            if (!byValue.containsKey(val))
                throw new IllegalStateException("Unknown User Generation Algorithm type: " + ArrayOps.byteToHex(val));
            return byValue.get(val);
        }
    }

    @JsMethod
    Type getType();

    String getExtraSalt();

    boolean includesBoxerGeneration();

    SecretGenerationAlgorithm withoutBoxer();

    static SecretGenerationAlgorithm getDefault(SafeRandom rnd) {
        return new ScryptGenerator(ScryptGenerator.MIN_MEMORY_COST, 8, 1, 64, generateSalt(rnd));
    }

    static SecretGenerationAlgorithm getLegacy(SafeRandom rnd) {
        return new ScryptGenerator(ScryptGenerator.MIN_MEMORY_COST, 8, 1, 96, generateSalt(rnd));
    }

    static SecretGenerationAlgorithm getDefaultWithoutExtraSalt() {
        return new ScryptGenerator(ScryptGenerator.MIN_MEMORY_COST, 8, 1, 96, "");
    }

    static String generateSalt(SafeRandom rnd) {
        return ArrayOps.bytesToHex(rnd.randomBytes(32));
    }

    static SecretGenerationAlgorithm withNewSalt(SecretGenerationAlgorithm alg, SafeRandom rnd) {
        if (alg instanceof ScryptGenerator) {
            ScryptGenerator scrypt = (ScryptGenerator) alg;
            return new ScryptGenerator(scrypt.memoryCost, scrypt.cpuCost, scrypt.parallelism, scrypt.outputBytes, generateSalt(rnd));
        }
        return alg;
    }

    static SecretGenerationAlgorithm fromCbor(Cborable cbor) {
        if (! (cbor instanceof CborObject.CborMap))
            throw new IllegalStateException("Incorrect cbor type for SecretGenerationAlgorithm: " + cbor);
        Type type = Type.byValue((int)((CborObject.CborMap) cbor).getLong("type"));
        if (type == Type.Scrypt)
            return ScryptGenerator.fromCbor(cbor);
        if (type == Type.Random)
            return new RandomSecretType();
        throw new IllegalStateException("Unimplemented UserGeneration type algorithm: " + type);
    }
}
