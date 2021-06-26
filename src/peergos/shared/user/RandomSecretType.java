package peergos.shared.user;

import peergos.shared.cbor.*;

import java.util.*;

public class RandomSecretType implements SecretGenerationAlgorithm {

    public RandomSecretType() {
    }

    @Override
    public CborObject toCbor() {
        Map<String, Cborable> props = new TreeMap<>();
        props.put("type", new CborObject.CborLong(getType().value));
        return CborObject.CborMap.build(props);
    }

    static RandomSecretType fromCbor(CborObject cbor) {
        return new RandomSecretType();
    }

    @Override
    public boolean includesBoxerGeneration() {
        return false;
    }

    @Override
    public SecretGenerationAlgorithm withoutBoxer() {
        return this;
    }

    @Override
    public Type getType() {
        return Type.Random;
    }

    @Override
    public String getExtraSalt() {
        return "";
    }
}
