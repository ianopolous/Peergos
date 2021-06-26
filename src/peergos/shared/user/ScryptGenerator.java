package peergos.shared.user;

import jsinterop.annotations.*;
import peergos.shared.cbor.*;

import java.util.*;

public class ScryptGenerator implements SecretGenerationAlgorithm {

    public static final int MIN_MEMORY_COST = 17;

    @JsProperty
    public final int memoryCost, cpuCost, parallelism, outputBytes;
    @JsProperty
    public final String extraSalt;

    public ScryptGenerator(int memoryCost, int cpuCost, int parallelism, int outputBytes, String extraSalt) {
        if (memoryCost < MIN_MEMORY_COST)
            throw new IllegalStateException("Scrypt memory cost must be >= 17");
        this.memoryCost = memoryCost;
        this.cpuCost = cpuCost;
        this.parallelism = parallelism;
        this.outputBytes = outputBytes;
        this.extraSalt = extraSalt;
    }

    @Override
    public boolean includesBoxerGeneration() {
        return outputBytes == 96;
    }

    @Override
    public SecretGenerationAlgorithm withoutBoxer() {
        return new ScryptGenerator(memoryCost, cpuCost, parallelism, 64, extraSalt);
    }

    @Override
    public String getExtraSalt() {
        return extraSalt;
    }

    @Override
    public CborObject toCbor() {
        Map<String, Cborable> props = new TreeMap<>();
        props.put("type", new CborObject.CborLong(getType().value));
        props.put("m", new CborObject.CborLong(memoryCost));
        props.put("c", new CborObject.CborLong(cpuCost));
        props.put("p", new CborObject.CborLong(parallelism));
        props.put("o", new CborObject.CborLong(outputBytes));
        props.put("s", new CborObject.CborString(extraSalt));
        return CborObject.CborMap.build(props);
    }

    static ScryptGenerator fromCbor(Cborable cbor) {
        CborObject.CborMap map = (CborObject.CborMap) cbor;
        int memoryCost = (int) map.getLong("m");
        int cpuCost = (int) map.getLong("c");
        int parallelsm = (int) map.getLong("p");
        int outputBytes = (int) map.getLong("o");
        String extraSalt = map.getString("s", "");
        return new ScryptGenerator(memoryCost, cpuCost, parallelsm, outputBytes, extraSalt);
    }

    @Override
    public Type getType() {
        return Type.Scrypt;
    }
}
