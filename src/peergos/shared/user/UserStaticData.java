package peergos.shared.user;
import java.util.logging.*;

import peergos.shared.cbor.*;
import peergos.shared.crypto.*;
import peergos.shared.crypto.symmetric.SymmetricKey;

import java.util.*;
import java.util.stream.*;

public class UserStaticData implements Cborable {
	private static final Logger LOG = Logger.getGlobal();
	private static final int PADDING_BLOCK_SIZE = 4096;

    private final PaddedCipherText allEntryPoints;


    public UserStaticData(PaddedCipherText allEntryPoints) {
        this.allEntryPoints = allEntryPoints;
    }

    public UserStaticData(List<EntryPoint> staticData, SymmetricKey rootKey, Optional<BoxingKeyPair> boxer) {
        this(PaddedCipherText.build(rootKey, new EntryPoints(EntryPoints.CURRENT_VERSION, staticData, boxer), PADDING_BLOCK_SIZE));
    }

    public EntryPoints getData(SymmetricKey rootKey) {
        return allEntryPoints.decrypt(rootKey, EntryPoints::fromCbor);
    }

    @Override
    public CborObject toCbor() {
        return allEntryPoints.toCbor();
    }

    public static UserStaticData fromCbor(Cborable cbor) {
        return new UserStaticData(PaddedCipherText.fromCbor(cbor));
    }

    public static class EntryPoints implements Cborable {
        private static final int CURRENT_VERSION = 2;

        private final long version;
        public final List<EntryPoint> entries;
        public final Optional<BoxingKeyPair> boxer; // this is only absent on legacy accounts

        public EntryPoints(long version, List<EntryPoint> entries, Optional<BoxingKeyPair> boxer) {
            this.version = version;
            this.entries = entries;
            this.boxer = boxer;
        }

        @Override
        public CborObject toCbor() {
            Map<String, Cborable> res = new TreeMap<>();
            res.put("v", new CborObject.CborLong(version));
            res.put("e", new CborObject.CborList(entries.stream()
                    .map(EntryPoint::toCbor)
                    .collect(Collectors.toList())));
            boxer.ifPresent(p -> res.put("b", p));
            return CborObject.CborMap.build(res);
        }

        public static EntryPoints fromCbor(Cborable cbor) {
            if (! (cbor instanceof CborObject.CborMap))
                throw new IllegalStateException("Incorrect cbor type for EntryPoints: " + cbor);
            CborObject.CborMap m = (CborObject.CborMap) cbor;
            long version = m.getLong("v");
            if (version > CURRENT_VERSION)
                throw new IllegalStateException("Unknown UserStaticData version: " + version);
            Optional<BoxingKeyPair> boxer = m.getOptional("b", BoxingKeyPair::fromCbor);
            return new EntryPoints(version,
                    m.getList("e")
                            .value.stream()
                            .map(EntryPoint::fromCbor)
                            .collect(Collectors.toList()),
                    boxer);
        }
    }
}
