package peergos.shared.user;

import peergos.shared.*;
import peergos.shared.cbor.*;
import peergos.shared.corenode.*;
import peergos.shared.crypto.*;
import peergos.shared.crypto.asymmetric.*;
import peergos.shared.crypto.hash.*;
import peergos.shared.crypto.symmetric.*;
import peergos.shared.io.ipfs.multihash.*;
import peergos.shared.mutable.*;
import peergos.shared.storage.*;
import peergos.shared.util.*;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.*;

public class WriterData implements Cborable {
    /**
     *  Represents the merkle node that a public key maps to
     */

    // the public signing key controlling this subspace
    public final PublicKeyHash controller;

    // publicly readable and present on owner keys
    public final Optional<SecretGenerationAlgorithm> generationAlgorithm;
    // This is the root of an InodeFileSystem containing read only caps to publicly shared files and folders
    public final Optional<Multihash> publicData;
    // The public boxing key to encrypt follow requests to
    public final Optional<PublicKeyHash> followRequestReceiver;
    // Any keys directly owned by the controller, that aren't named, in a champ<key hash, owner proof>
    public final Optional<Multihash> ownedKeys;

    // Any keys directly owned by the controller that have specific labels
    public final Map<String, OwnerProof> namedOwnedKeys;

    // Encrypted entry points to our file systems (present on owner keys)
    public final Optional<UserStaticData> staticData;
    // This is the root of a champ containing the controller's filesystem (present on writer keys)
    public final Optional<Multihash> tree;

    /**
     *
     * @param controller the public signing key that controls writing to this subspace
     * @param generationAlgorithm The algorithm used to create the users key pairs and root key from the username and password
     * @param publicData A readable pointer to a subtree made public by this key
     * @param ownedKeys Any public keys owned by this key
     * @param staticData Any static data owner by this key (list of entry points)
     * @param tree Any file tree owned by this key
     */
    public WriterData(PublicKeyHash controller,
                      Optional<SecretGenerationAlgorithm> generationAlgorithm,
                      Optional<Multihash> publicData,
                      Optional<PublicKeyHash> followRequestReceiver,
                      Optional<Multihash> ownedKeys,
                      Map<String, OwnerProof> namedOwnedKeys,
                      Optional<UserStaticData> staticData,
                      Optional<Multihash> tree) {
        this.controller = controller;
        this.generationAlgorithm = generationAlgorithm;
        this.publicData = publicData;
        this.followRequestReceiver = followRequestReceiver;
        this.ownedKeys = ownedKeys;
        this.namedOwnedKeys = namedOwnedKeys;
        this.staticData = staticData;
        this.tree = tree;
    }

    public WriterData withChamp(Multihash treeRoot) {
        return new WriterData(controller, generationAlgorithm, publicData, followRequestReceiver, ownedKeys, namedOwnedKeys, staticData, Optional.of(treeRoot));
    }

    public WriterData withPublicRoot(Multihash publicChampRoot) {
        return new WriterData(controller, generationAlgorithm, Optional.of(publicChampRoot), followRequestReceiver, ownedKeys, namedOwnedKeys, staticData, tree);
    }

    public WriterData withOwnedRoot(Multihash ownedRoot) {
        return new WriterData(controller, generationAlgorithm, publicData, followRequestReceiver, Optional.of(ownedRoot), namedOwnedKeys, staticData, tree);
    }

    public CompletableFuture<WriterData> addOwnedKey(PublicKeyHash owner,
                                                     SigningPrivateKeyAndPublicHash signer,
                                                     OwnerProof newOwned,
                                                     ContentAddressedStorage ipfs,
                                                     Hasher hasher) {
        return IpfsTransaction.call(owner,
                tid -> (! ownedKeys.isPresent() ?
                        OwnedKeyChamp.createEmpty(owner, signer, ipfs, hasher, tid)
                                .thenCompose(root -> OwnedKeyChamp.build(root, ipfs, hasher)) :
                        getOwnedKeyChamp(ipfs, hasher))
                        .thenCompose(champ -> champ.add(owner, signer, newOwned, hasher, tid))
                        .thenApply(newRoot -> new WriterData(controller, generationAlgorithm, publicData, followRequestReceiver,
                                Optional.of(newRoot), namedOwnedKeys, staticData, tree)), ipfs);
    }

    public CompletableFuture<Snapshot> addOwnedKeyAndCommit(PublicKeyHash owner,
                                                            SigningPrivateKeyAndPublicHash signer,
                                                            OwnerProof newOwned,
                                                            MaybeMultihash currentHash,
                                                            NetworkAccess network,
                                                            TransactionId tid) {
        return getOwnedKeyChamp(network.dhtClient, network.hasher)
                .thenCompose(champ -> champ.add(owner, signer, newOwned, network.hasher, tid)
                        .thenApply(newRoot -> new WriterData(controller, generationAlgorithm, publicData,
                                followRequestReceiver, Optional.of(newRoot), namedOwnedKeys, staticData, tree)))
                .thenCompose(wd -> wd.commit(owner, signer, currentHash, network, tid));
    }

    public CompletableFuture<WriterData> removeOwnedKey(PublicKeyHash owner,
                                                        SigningPrivateKeyAndPublicHash signer,
                                                        PublicKeyHash ownedKey,
                                                        ContentAddressedStorage ipfs,
                                                        Hasher hasher) {

        return getOwnedKeyChamp(ipfs, hasher)
                .thenCompose(champ -> IpfsTransaction.call(owner,
                        tid -> champ.remove(owner, signer, ownedKey, tid), ipfs)
                        .thenApply(newRoot -> new WriterData(controller, generationAlgorithm, publicData, followRequestReceiver,
                                Optional.of(newRoot), namedOwnedKeys, staticData, tree)));
    }

    public CompletableFuture<Boolean> ownsKey(PublicKeyHash identityKey,
                                              PublicKeyHash ownedKey,
                                              ContentAddressedStorage ipfs,
                                              MutablePointers mutable,
                                              Hasher hasher) {
        return getOwnedKeyChamp(ipfs, hasher)
                .thenCompose(champ -> champ.get(ownedKey)
                        .thenApply(Optional::isPresent)
                        .thenCompose(direct -> {
                            if (direct)
                                return Futures.of(true);
                            return champ.applyToAllMappings(false,
                                    (b, p) -> {
                                        if (b) // exit early if we find a match
                                            return Futures.of(b);
                                        PublicKeyHash childKey = p.left;
                                        return UserContext.getWriterData(ipfs, mutable, identityKey, childKey)
                                                .thenCompose(wd -> wd.props.ownsKey(identityKey, ownedKey, ipfs, mutable, hasher));
                                    },
                                    ipfs);
                        }));
    }

    public CompletableFuture<OwnedKeyChamp> getOwnedKeyChamp(ContentAddressedStorage ipfs, Hasher hasher) {
        return ownedKeys.map(root -> OwnedKeyChamp.build(root, ipfs, hasher))
                .orElseThrow(() -> new IllegalStateException("Owned key champ absent!"));
    }

    private <T> CompletableFuture<Set<T>> applyToOwnedKeys(Function<OwnedKeyChamp, CompletableFuture<Set<T>>> processor,
                                                           ContentAddressedStorage ipfs,
                                                           Hasher hasher) {
        return ownedKeys.map(x -> getOwnedKeyChamp(ipfs, hasher).thenCompose(processor))
                .orElse(CompletableFuture.completedFuture(Collections.emptySet()));
    }

    public WriterData addNamedKey(String name, OwnerProof newNamedKey) {
        Map<String, OwnerProof> updated = new TreeMap<>(namedOwnedKeys);
        updated.put(name, newNamedKey);
        return new WriterData(controller, generationAlgorithm, publicData, followRequestReceiver, ownedKeys, updated, staticData, tree);
    }

    public WriterData withStaticData(Optional<UserStaticData> entryPoints) {
        return new WriterData(controller, generationAlgorithm, publicData, followRequestReceiver, ownedKeys, namedOwnedKeys, entryPoints, tree);
    }

    public static CompletableFuture<WriterData> createEmpty(PublicKeyHash owner,
                                                            SigningPrivateKeyAndPublicHash writer,
                                                            ContentAddressedStorage ipfs,
                                                            Hasher hasher,
                                                            TransactionId tid) {
        return OwnedKeyChamp.createEmpty(owner, writer, ipfs, hasher, tid)
                .thenApply(ownedRoot -> new WriterData(writer.publicKeyHash,
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.of(ownedRoot),
                        Collections.emptyMap(),
                        Optional.empty(),
                        Optional.empty()));
    }

    public static CompletableFuture<WriterData> createEmptyWithStaticData(PublicKeyHash owner,
                                                                          SigningPrivateKeyAndPublicHash writer,
                                                                          Optional<PublicKeyHash> followRequestReceiver,
                                                                          SymmetricKey rootKey,
                                                                          Optional<BoxingKeyPair> boxer,
                                                                          SecretGenerationAlgorithm algorithm,
                                                                          ContentAddressedStorage ipfs,
                                                                          Hasher hasher,
                                                                          TransactionId tid) {
        return OwnedKeyChamp.createEmpty(owner, writer, ipfs, hasher, tid)
                .thenApply(ownedRoot -> new WriterData(writer.publicKeyHash,
                        Optional.of(algorithm),
                        Optional.empty(),
                        followRequestReceiver,
                        Optional.of(ownedRoot),
                        Collections.emptyMap(),
                        Optional.of(new UserStaticData(Collections.emptyList(), rootKey, boxer)),
                        Optional.empty()));
    }

    public CommittedWriterData committed(MaybeMultihash hash) {
        return new CommittedWriterData(hash, this);
    }

    public CompletableFuture<WriterData> changeKeys(SigningPrivateKeyAndPublicHash oldSigner,
                                                    SigningPrivateKeyAndPublicHash signer,
                                                    BoxingKeyPair followRequestReceiver,
                                                    SymmetricKey currentKey,
                                                    SymmetricKey newKey,
                                                    SecretGenerationAlgorithm newAlgorithm,
                                                    Map<PublicKeyHash, SigningPrivateKeyAndPublicHash> ownedKeys,
                                                    NetworkAccess network) {

        network.synchronizer.putEmpty(oldSigner.publicKeyHash, signer.publicKeyHash);
        return network.synchronizer.applyUpdate(oldSigner.publicKeyHash, signer,
                (wd, tid) -> {
                    Optional<UserStaticData> newEntryPoints = staticData
                            .map(sd -> {
                                UserStaticData.EntryPoints staticData = sd.getData(currentKey);
                                Optional<BoxingKeyPair> boxer = Optional.of(staticData.boxer.orElse(followRequestReceiver));
                                return new UserStaticData(staticData.entries, newKey, boxer);
                            });
                    return network.hasher.sha256(followRequestReceiver.serialize())
                            .thenCompose(boxerHash -> network.dhtClient.putBoxingKey(oldSigner.publicKeyHash,
                            oldSigner.secret.signMessage(boxerHash),
                            followRequestReceiver.publicBoxingKey, tid
                    )).thenCompose(boxerHash -> OwnedKeyChamp.createEmpty(oldSigner.publicKeyHash, oldSigner,
                            network.dhtClient, network.hasher, tid)
                            .thenCompose(ownedRoot -> {
                                Map<String, OwnerProof> newNamedOwnedKeys = namedOwnedKeys.entrySet()
                                        .stream()
                                        .collect(Collectors.toMap(e -> e.getKey(),
                                                e -> OwnerProof.build(ownedKeys.get(e.getValue().ownedKey), signer.publicKeyHash)));

                                // need to add all our owned keys back with the new owner, except for the new signer itself
                                WriterData base = new WriterData(signer.publicKeyHash,
                                        Optional.of(newAlgorithm),
                                        publicData,
                                        Optional.of(new PublicKeyHash(boxerHash)),
                                        Optional.of(ownedRoot),
                                        newNamedOwnedKeys,
                                        newEntryPoints,
                                        tree);
                                return getOwnedKeyChamp(network.dhtClient, network.hasher)
                                        .thenCompose(okChamp -> okChamp.applyToAllMappings(base, (nwd, p) ->
                                                p.left.equals(signer.publicKeyHash) ? Futures.of(nwd) :
                                                nwd.addOwnedKey(oldSigner.publicKeyHash, signer,
                                                        OwnerProof.build(ownedKeys.get(p.left), signer.publicKeyHash),
                                                        network.dhtClient, network.hasher), network.dhtClient)
                                        );
                            }));
                })
                .thenApply(version -> version.get(signer).props)
                .exceptionally(t -> {
                    if (t.getMessage().contains("cas+failed"))
                        throw new IllegalStateException("You cannot reuse a previous password!");
                    throw new RuntimeException(t.getCause());
                });
    }

    public CompletableFuture<Snapshot> commit(PublicKeyHash owner,
                                              SigningPrivateKeyAndPublicHash signer,
                                              MaybeMultihash currentHash,
                                              NetworkAccess network,
                                              TransactionId tid) {
        return commit(owner, signer, currentHash, network.mutable, network.dhtClient, network.hasher, tid);
    }

    public CompletableFuture<Snapshot> commit(PublicKeyHash owner,
                                              SigningPrivateKeyAndPublicHash signer,
                                              MaybeMultihash currentHash,
                                              MutablePointers mutable,
                                              ContentAddressedStorage immutable,
                                              Hasher hasher,
                                              TransactionId tid) {
        byte[] raw = serialize();

        return hasher.sha256(raw)
                .thenCompose(hash -> immutable.put(owner, signer.publicKeyHash, signer.secret.signMessage(hash), raw, tid))
                .thenCompose(blobHash -> immutable.flush().thenApply(x -> blobHash))
                .thenCompose(blobHash -> {
                    MaybeMultihash newHash = MaybeMultihash.of(blobHash);
                    if (newHash.equals(currentHash)) {
                        // nothing has changed
                        CommittedWriterData committed = committed(newHash);
                        return CompletableFuture.completedFuture(new Snapshot(signer.publicKeyHash, committed));
                    }
                    HashCasPair cas = new HashCasPair(currentHash, newHash);
                    byte[] signed = signer.secret.signMessage(cas.serialize());
                    return mutable.setPointer(owner, signer.publicKeyHash, signed)
                            .thenApply(res -> {
                                if (!res)
                                    throw new IllegalStateException("Corenode Crypto CAS failed!");
                                CommittedWriterData committed = committed(newHash);
                                return new Snapshot(signer.publicKeyHash, committed);
                            });
                });
    }

    @Override
    public CborObject toCbor() {
        Map<String, Cborable> result = new TreeMap<>();

        result.put("controller", new CborObject.CborMerkleLink(controller));
        generationAlgorithm.ifPresent(alg -> result.put("algorithm", alg.toCbor()));
        publicData.ifPresent(root -> result.put("public", new CborObject.CborMerkleLink(root)));
        followRequestReceiver.ifPresent(boxer -> result.put("inbound", new CborObject.CborMerkleLink(boxer)));
        ownedKeys.ifPresent(root -> result.put("owned", new CborObject.CborMerkleLink(root)));
        if (! namedOwnedKeys.isEmpty())
            result.put("named", CborObject.CborMap.build(new HashMap<>(namedOwnedKeys)));
        staticData.ifPresent(sd -> result.put("static", sd.toCbor()));
        tree.ifPresent(tree -> result.put("tree", new CborObject.CborMerkleLink(tree)));
        return CborObject.CborMap.build(result);
    }

    public static WriterData fromCbor(CborObject cbor) {
        if (! ( cbor instanceof CborObject.CborMap))
            throw new IllegalStateException("Cbor for WriterData should be a map! " + cbor);

        CborObject.CborMap m = (CborObject.CborMap) cbor;

        PublicKeyHash controller = m.get("controller", PublicKeyHash::fromCbor);
        Optional<SecretGenerationAlgorithm> algo  = m.getOptional("algorithm", SecretGenerationAlgorithm::fromCbor);
        Optional<Multihash> publicData = m.getOptional("public", val -> ((CborObject.CborMerkleLink)val).target);
        Optional<PublicKeyHash> followRequestReceiver = m.getOptional("inbound", PublicKeyHash::fromCbor);
        Optional<Multihash> owned = m.getOptional("owned", val -> ((CborObject.CborMerkleLink)val).target);

        Map<String, OwnerProof> named = m.getOptional("named", c -> (CborObject.CborMap)c)
                .map(map -> map.toMap(k -> ((CborObject.CborString)k).value, OwnerProof::fromCbor))
                .orElseGet(() -> Collections.emptyMap());

        Optional<UserStaticData> staticData = m.getOptional("static", UserStaticData::fromCbor);
        Optional<Multihash> tree = m.getOptional("tree", val -> ((CborObject.CborMerkleLink)val).target);
        return new WriterData(controller, algo, publicData, followRequestReceiver, owned, named, staticData, tree);
    }

    public static CompletableFuture<Map<PublicKeyHash, byte[]>> getUserSnapshot(String username,
                                                                                CoreNode core,
                                                                                MutablePointers mutable,
                                                                                ContentAddressedStorage dht,
                                                                                Hasher hasher) {
        return core.getPublicKeyHash(username)
                .thenCompose(publicKeyHash -> publicKeyHash
                        .map(h -> getUserSnapshotRecursive(h, h, Collections.emptyMap(), mutable, dht, hasher))
                        .orElseGet(() -> CompletableFuture.completedFuture(Collections.emptyMap())));
    }

    public static CompletableFuture<Map<PublicKeyHash, byte[]>> getUserSnapshotRecursive(PublicKeyHash owner,
                                                                                         PublicKeyHash writer,
                                                                                         Map<PublicKeyHash, byte[]> alreadyDone,
                                                                                         MutablePointers mutable,
                                                                                         ContentAddressedStorage ipfs,
                                                                                         Hasher hasher) {
        return getDirectOwnedKeys(owner, writer, mutable, ipfs, hasher)
                .thenCompose(directOwned -> {
                    Set<PublicKeyHash> newKeys = directOwned.stream().
                            filter(h -> ! alreadyDone.containsKey(h))
                            .collect(Collectors.toSet());
                    Map<PublicKeyHash, byte[]> done = new HashMap<>(alreadyDone);
                    return mutable.getPointer(owner, writer).thenCompose(val -> {
                        if (val.isPresent())
                            done.put(writer, val.get());
                        BiFunction<Map<PublicKeyHash, byte[]>, PublicKeyHash,
                                CompletableFuture<Map<PublicKeyHash, byte[]>>> composer =
                                (a, w) -> getUserSnapshotRecursive(owner, w, a, mutable, ipfs, hasher)
                                        .thenApply(ws ->
                                                Stream.concat(
                                                        ws.entrySet().stream().filter(e -> ! a.containsKey(e.getKey())),
                                                        a.entrySet().stream())
                                                        .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue())));
                        return Futures.reduceAll(newKeys, done,
                                composer,
                                (a, b) -> Stream.concat(
                                        a.entrySet().stream().filter(e -> ! b.containsKey(e.getKey())),
                                        b.entrySet().stream())
                                        .collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue())));
                    });
                });
    }

    public static CompletableFuture<Set<PublicKeyHash>> getOwnedKeysRecursive(String username,
                                                                              CoreNode core,
                                                                              MutablePointers mutable,
                                                                              ContentAddressedStorage dht,
                                                                              Hasher hasher) {
        return core.getPublicKeyHash(username)
                .thenCompose(publicKeyHash -> publicKeyHash
                        .map(h -> getOwnedKeysRecursive(h, h, mutable, dht, hasher))
                        .orElseGet(() -> CompletableFuture.completedFuture(Collections.emptySet())));
    }

    public static CompletableFuture<Set<PublicKeyHash>> getOwnedKeysRecursive(PublicKeyHash owner,
                                                                              PublicKeyHash writer,
                                                                              MutablePointers mutable,
                                                                              ContentAddressedStorage ipfs,
                                                                              Hasher hasher) {
        return getOwnedKeysRecursive(owner, writer, Collections.emptySet(), mutable, ipfs, hasher);
    }

    private static CompletableFuture<Set<PublicKeyHash>> getOwnedKeysRecursive(PublicKeyHash owner,
                                                                               PublicKeyHash writer,
                                                                               Set<PublicKeyHash> alreadyDone,
                                                                               MutablePointers mutable,
                                                                               ContentAddressedStorage ipfs,
                                                                               Hasher hasher) {
        return getDirectOwnedKeys(owner, writer, mutable, ipfs, hasher)
                .thenCompose(directOwned -> {
                    Set<PublicKeyHash> newKeys = directOwned.stream().
                            filter(h -> ! alreadyDone.contains(h))
                            .collect(Collectors.toSet());
                    Set<PublicKeyHash> done = new HashSet<>(alreadyDone);
                    done.add(writer);
                    BiFunction<Set<PublicKeyHash>, PublicKeyHash, CompletableFuture<Set<PublicKeyHash>>> composer =
                            (a, w) -> getOwnedKeysRecursive(owner, w, a, mutable, ipfs, hasher)
                                    .thenApply(ws ->
                                            Stream.concat(ws.stream(), a.stream())
                                                    .collect(Collectors.toSet()));
                    return Futures.reduceAll(newKeys, done,
                            composer,
                            (a, b) -> Stream.concat(a.stream(), b.stream())
                                    .collect(Collectors.toSet()));
                });
    }

    public static CompletableFuture<Set<PublicKeyHash>> getDirectOwnedKeys(PublicKeyHash owner,
                                                                           PublicKeyHash writer,
                                                                           MutablePointers mutable,
                                                                           ContentAddressedStorage ipfs,
                                                                           Hasher hasher) {
        return mutable.getPointerTarget(owner, writer, ipfs)
                .thenCompose(h -> getDirectOwnedKeys(writer, h, ipfs, hasher));
    }

    public static CompletableFuture<Set<PublicKeyHash>> getDirectOwnedKeys(PublicKeyHash writer,
                                                                           MaybeMultihash root,
                                                                           ContentAddressedStorage ipfs,
                                                                           Hasher hasher) {
        if (! root.isPresent())
            return CompletableFuture.completedFuture(Collections.emptySet());

        BiFunction<Set<OwnerProof>, Pair<PublicKeyHash, OwnerProof>, CompletableFuture<Set<OwnerProof>>>
                composer = (acc, pair) -> CompletableFuture.completedFuture(Stream.concat(acc.stream(), Stream.of(pair.right))
                .collect(Collectors.toSet()));

        BiFunction<Set<PublicKeyHash>, OwnerProof, CompletableFuture<Set<PublicKeyHash>>> proofComposer =
                (acc, proof) -> proof.getOwner(ipfs)
                        .thenApply(claimedWriter -> Stream.concat(acc.stream(), claimedWriter.equals(writer) ?
                                Stream.of(proof.ownedKey) :
                                Stream.empty()).collect(Collectors.toSet()));

        return getWriterData(root.get(), ipfs)
                .thenCompose(wd -> wd.props.applyToOwnedKeys(owned ->
                        owned.applyToAllMappings(Collections.emptySet(), composer, ipfs), ipfs, hasher)
                        .thenApply(owned -> Stream.concat(owned.stream(),
                                wd.props.namedOwnedKeys.values().stream()).collect(Collectors.toSet())))
                .thenCompose(all -> Futures.reduceAll(all, Collections.emptySet(),
                        proofComposer,
                        (a, b) -> Stream.concat(a.stream(), b.stream())
                                .collect(Collectors.toSet())));
    }

    public static CompletableFuture<CommittedWriterData> getWriterData(PublicKeyHash owner,
                                                                       PublicKeyHash controller,
                                                                       MutablePointers mutable,
                                                                       ContentAddressedStorage dht) {
        return mutable.getPointerTarget(owner, controller, dht)
                .thenCompose(opt -> {
                    if (! opt.isPresent())
                        throw new IllegalStateException("No root pointer present for controller " + controller);
                    return getWriterData(opt.get(), dht);
                });
    }

    public static CompletableFuture<CommittedWriterData> getWriterData(Multihash hash, ContentAddressedStorage dht) {
        return dht.get(hash)
                .thenApply(cborOpt -> {
                    if (! cborOpt.isPresent())
                        throw new IllegalStateException("Couldn't retrieve WriterData from dht! " + hash);
                    return new CommittedWriterData(MaybeMultihash.of(hash), WriterData.fromCbor(cborOpt.get()));
                });
    }
}
