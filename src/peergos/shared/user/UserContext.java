package peergos.shared.user;

import java.io.*;
import java.util.logging.*;

import peergos.shared.fingerprint.*;
import peergos.shared.inode.*;
import peergos.shared.user.fs.cryptree.*;
import peergos.shared.user.fs.transaction.TransactionService;
import peergos.shared.user.fs.transaction.TransactionServiceImpl;
import peergos.shared.*;
import peergos.shared.cbor.*;
import peergos.shared.corenode.*;
import peergos.shared.crypto.*;
import peergos.shared.crypto.asymmetric.*;
import peergos.shared.crypto.hash.*;
import peergos.shared.crypto.symmetric.*;
import peergos.shared.io.ipfs.multihash.Multihash;
import peergos.shared.mutable.*;
import peergos.shared.social.*;
import peergos.shared.storage.*;
import peergos.shared.user.fs.*;
import peergos.shared.util.*;

import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.*;

import jsinterop.annotations.*;

/**
 * The UserContext class represents a logged in user, or a retrieved public link and the resulting view of the global
 * filesystem.
 */
public class UserContext {
    private static final Logger LOG = Logger.getGlobal();

    public static final String SHARED_DIR_NAME = "shared";
    public static final String POSTS_DIR_NAME = ".posts";
    public static final String GROUPS_FILENAME = ".groups.cbor"; // no clash possible with usernames possible because of dot
    public static final String FEED_DIR_NAME = ".feed";
    public static final String TRANSACTIONS_DIR_NAME = ".transactions";
    public static final String FRIEND_ANNOTATIONS_FILE_NAME = ".annotations";

    public static final String ENTRY_POINTS_FROM_FRIENDS_FILENAME = ".from-friends.cborstream";
    public static final String ENTRY_POINTS_FROM_FRIENDS_GROUPS_FILENAME = ".groups-from-friends.cborstream";
    public static final String SOCIAL_STATE_FILENAME = ".social-state.cbor";
    public static final String BLOCKED_USERNAMES_FILE = ".blocked-usernames.txt";

    @JsProperty
    public final String username;
    public final SigningPrivateKeyAndPublicHash signer;
    private final BoxingKeyPair boxer;
    private final SymmetricKey rootKey;

    private final WriteSynchronizer writeSynchronizer;
    private final TransactionService transactions;
    private final IncomingCapCache capCache;
    public final SharedWithCache sharedWithCache;

    // The root of the global filesystem as viewed by this context
    @JsProperty
    public TrieNode entrie; // ba dum che!

    // Contact external world
    @JsProperty
    public final NetworkAccess network;

    // In process only
    @JsProperty
    public final Crypto crypto;

    public UserContext(String username,
                       SigningPrivateKeyAndPublicHash signer,
                       BoxingKeyPair boxer,
                       SymmetricKey rootKey,
                       NetworkAccess network,
                       Crypto crypto,
                       CommittedWriterData userData,
                       TrieNode entrie,
                       TransactionService transactions,
                       IncomingCapCache capCache) {
        this.username = username;
        this.signer = signer;
        this.boxer = boxer;
        this.rootKey = rootKey;
        this.network = network;
        this.crypto = crypto;
        this.entrie = entrie;
        this.writeSynchronizer = network.synchronizer;
        if (signer != null) {
            writeSynchronizer.put(signer.publicKeyHash, signer.publicKeyHash, userData);
        }
        this.transactions = transactions;
        this.capCache = capCache;
        this.sharedWithCache = new SharedWithCache(this::getByPath, username, network, crypto);
    }

    private static CompletableFuture<TransactionService> buildTransactionService(TrieNode root,
                                                                                 String username,
                                                                                 NetworkAccess network,
                                                                                 Crypto crypto) {
        return root.getByPath(username, crypto.hasher, network)
                .thenApply(Optional::get)
                .thenCompose(home -> home.getChild(TRANSACTIONS_DIR_NAME, crypto.hasher, network))
                .thenApply(Optional::get)
                .thenApply(txnDir -> new TransactionServiceImpl(network, crypto, txnDir));
    }

    private static CompletableFuture<IncomingCapCache> buildCapCache(TrieNode root,
                                                                     String username,
                                                                     NetworkAccess network,
                                                                     Crypto crypto) {
        return root.getByPath(username, crypto.hasher, network)
                .thenApply(Optional::get)
                .thenCompose(home -> home.getOrMkdirs(Paths.get(CapabilityStore.CAPABILITY_CACHE_DIR), network, true, crypto))
                .thenCompose(cacheRoot -> IncomingCapCache.build(cacheRoot, crypto, network));
    }

    @JsMethod
    public TransactionService getTransactionService() {
        return transactions;
    }

    public static CompletableFuture<UserContext> signIn(String username, String password, NetworkAccess network
            , Crypto crypto) {
        return signIn(username, password, network, crypto, t -> {});
    }

    @JsMethod
    public static CompletableFuture<UserContext> signIn(String username, String password, NetworkAccess network,
                                                        Crypto crypto, Consumer<String> progressCallback) {
        return Futures.asyncExceptionally(() -> getWriterDataCbor(network, username),
                e ->  {
                    if (e.getMessage().contains("hash not present"))
                        return Futures.errored(new IllegalStateException("User has been deleted. Did you mean a different username?"));
                    else if (e.getMessage().contains("No public-key for user"))
                        return Futures.errored(new IllegalStateException("Unknown username. Did you enter it correctly?"));
                    else
                        return Futures.errored(e);
                }).thenCompose(pair -> {
            SecretGenerationAlgorithm algorithm = WriterData.fromCbor(pair.right).generationAlgorithm
                    .orElseThrow(() -> new IllegalStateException("No login algorithm specified in user data!"));
            progressCallback.accept("Generating keys");
            return UserUtil.generateUser(username, password, crypto.hasher, crypto.symmetricProvider,
                    crypto.random, crypto.signer, crypto.boxer, algorithm)
                    .thenCompose(userWithRoot -> {
                        progressCallback.accept("Logging in");
                        return login(username, userWithRoot, pair, network, crypto, progressCallback);
                    });
        }).exceptionally(Futures::logAndThrow);
    }

    public static CompletableFuture<UserContext> signIn(String username, UserWithRoot userWithRoot, NetworkAccess network
            , Crypto crypto, Consumer<String> progressCallback) {
        progressCallback.accept("Logging in");
        return getWriterDataCbor(network, username)
                .thenCompose(pair -> login(username, userWithRoot, pair, network, crypto, progressCallback))
                .exceptionally(Futures::logAndThrow);
    }

    private static CompletableFuture<UserContext> login(String username,
                                                        UserWithRoot userWithRoot,
                                                        Pair<Multihash, CborObject> pair,
                                                        NetworkAccess network,
                                                        Crypto crypto,
                                                        Consumer<String> progressCallback) {
        try {
            WriterData userData = WriterData.fromCbor(pair.right);
            return createOurFileTreeOnly(username, userWithRoot.getRoot(), userData, network, crypto)
                    .thenCompose(root -> TofuCoreNode.load(username, root, network, crypto)
                            .thenCompose(tofuCorenode -> {
                                SigningPrivateKeyAndPublicHash signer = new SigningPrivateKeyAndPublicHash(userData.controller, userWithRoot.getUser().secretSigningKey);
                                return buildTransactionService(root, username, network, crypto)
                                        .thenCompose(transactions -> buildCapCache(root, username, network, crypto)
                                                .thenCompose(capCache -> {
                                                    UserStaticData.EntryPoints staticData = userData.staticData.get().getData(userWithRoot.getRoot());
                                                    UserContext result = new UserContext(username,
                                                            signer,
                                                            staticData.boxer.orElse(userWithRoot.getBoxingPair()),
                                                            userWithRoot.getRoot(),
                                                            network.withCorenode(tofuCorenode),
                                                            crypto,
                                                            new CommittedWriterData(MaybeMultihash.of(pair.left), userData),
                                                            root,
                                                            transactions,
                                                            capCache);

                                                    return result.init(progressCallback)
                                                            .exceptionally(Futures::logAndThrow);
                                                }));
                            }));
        } catch (Throwable t) {
            throw new IllegalStateException("Incorrect password");
        }
    }

    @JsMethod
    public static CompletableFuture<UserContext> signUp(String username,
                                                        String password,
                                                        String token,
                                                        NetworkAccess network,
                                                        Crypto crypto,
                                                        Consumer<String> progressCallback) {
        // set claim expiry to two months from now
        LocalDate expiry = LocalDate.now().plusMonths(2);
        SecretGenerationAlgorithm algorithm = SecretGenerationAlgorithm.getDefault(crypto.random);
        return signUpGeneral(username, password, token, expiry, network, crypto, algorithm, progressCallback);
    }

    public static CompletableFuture<UserContext> signUp(String username,
                                                        String password,
                                                        String token,
                                                        NetworkAccess network,
                                                        Crypto crypto) {
        // set claim expiry to two months from now
        LocalDate expiry = LocalDate.now().plusMonths(2);
        SecretGenerationAlgorithm algorithm = SecretGenerationAlgorithm.getDefault(crypto.random);
        return signUpGeneral(username, password, token, expiry, network, crypto, algorithm, t -> {});
    }

    public static CompletableFuture<UserContext> signUpGeneral(String username,
                                                               String password,
                                                               String token,
                                                               LocalDate expiry,
                                                               NetworkAccess initialNetwork,
                                                               Crypto crypto,
                                                               SecretGenerationAlgorithm algorithm,
                                                               Consumer<String> progressCallback) {
        // Using a local OpLog that doesn't commit anything allows us to group all the updates into a single atomic call
        OpLog opLog = new OpLog(new ArrayList<>());
        NetworkAccess network = NetworkAccess.nonCommittingForSignup(opLog, opLog, crypto.hasher);
        progressCallback.accept("Generating keys");
        return initialNetwork.coreNode.getChain(username)
                .thenApply(existing -> {
                    if (existing.size() > 0)
                        throw new IllegalStateException("User already exists!");
                    return true;
                })
                .thenCompose(x -> UserUtil.generateUser(username, password, crypto.hasher, crypto.symmetricProvider,
                        crypto.random, crypto.signer, crypto.boxer, algorithm))
                .thenCompose(userWithRoot -> {
                    PublicSigningKey publicSigningKey = userWithRoot.getUser().publicSigningKey;
                    SecretSigningKey secretSigningKey = userWithRoot.getUser().secretSigningKey;
                    PublicKeyHash signerHash = ContentAddressedStorage.hashKey(publicSigningKey);
                    SigningPrivateKeyAndPublicHash signer = new SigningPrivateKeyAndPublicHash(signerHash, secretSigningKey);
                    progressCallback.accept("Registering username");
                    return initialNetwork.dhtClient.id()
                            .thenApply(id -> UserPublicKeyLink.createInitial(signer, username, expiry, Arrays.asList(id)))
                            .thenCompose(chain -> IpfsTransaction.call(signerHash, tid -> network.dhtClient.putSigningKey(
                                    secretSigningKey.signMessage(publicSigningKey.serialize()),
                                    signerHash,
                                    publicSigningKey, tid).thenCompose(returnedSignerHash -> {
                                PublicBoxingKey publicBoxingKey = userWithRoot.getBoxingPair().publicBoxingKey;
                                return crypto.hasher.sha256(publicBoxingKey.serialize())
                                        .thenCompose(boxerHash -> network.dhtClient.putBoxingKey(signerHash,
                                                secretSigningKey.signMessage(boxerHash), publicBoxingKey, tid));
                            }).thenCompose(boxerHash -> {
                                progressCallback.accept("Creating filesystem");
                                return WriterData.createEmptyWithStaticData(signerHash,
                                        signer,
                                        Optional.of(new PublicKeyHash(boxerHash)),
                                        userWithRoot.getRoot(),
                                        algorithm.includesBoxerGeneration() ? Optional.empty() : Optional.of(userWithRoot.getBoxingPair()),
                                        algorithm,
                                        network.dhtClient, network.hasher, tid).thenCompose(newUserData -> {

                                    CommittedWriterData notCommitted = new CommittedWriterData(MaybeMultihash.empty(), newUserData);
                                    network.synchronizer.put(signer.publicKeyHash, signer.publicKeyHash, notCommitted);
                                    return network.synchronizer.applyComplexUpdate(signerHash, signer,
                                            (s, committer) -> newUserData.commit(signerHash, signer, MaybeMultihash.empty(), network, tid));
                                });
                            }), network.dhtClient)
                                    .thenCompose(snapshot -> {
                                        LOG.info("Creating user's root directory");
                                        long t1 = System.currentTimeMillis();
                                        return createEntryDirectory(signer, username, userWithRoot.getRoot(), network, crypto)
                                                .thenCompose(globalRoot -> {
                                                    LOG.info("Creating root directory took " + (System.currentTimeMillis() - t1) + " mS");
                                                    return createSpecialDirectory(globalRoot, username, SHARED_DIR_NAME, network, crypto);
                                                })
                                                .thenCompose(globalRoot -> createSpecialDirectory(globalRoot, username,
                                                        TRANSACTIONS_DIR_NAME, network, crypto))
                                                .thenCompose(globalRoot -> createSpecialDirectory(globalRoot, username,
                                                        CapabilityStore.CAPABILITY_CACHE_DIR, network, crypto))
                                                .thenCompose(x -> signupWithRetry(username, chain.get(0), token, opLog, crypto.hasher, initialNetwork, progressCallback))
                                                .thenCompose(y -> signIn(username, userWithRoot, initialNetwork, crypto, progressCallback));
                                    }));
                }).exceptionally(Futures::logAndThrow);
    }

    @JsMethod
    public CompletableFuture<Boolean> ensureUsernameClaimRenewed() {
        return getUsernameClaimExpiry()
                .thenCompose(expiry -> expiry.isBefore(LocalDate.now().plusMonths(1)) ?
                        renewUsernameClaim(LocalDate.now().plusMonths(2)) :
                        CompletableFuture.completedFuture(true));
    }

    private static CompletableFuture<TrieNode> createSpecialDirectory(TrieNode globalRoot,
                                                                      String username,
                                                                      String dirName,
                                                                      NetworkAccess network,
                                                                      Crypto crypto) {
        return globalRoot.getByPath(username, crypto.hasher, network)
                .thenCompose(root -> root.get().mkdir(dirName, network, true, crypto))
                .thenApply(x -> globalRoot);
    }

    @JsType
    public static class EncryptedURL {
        public static final int PAD_TO_SIZE = 50;
        public final String base64Nonce, base64Ciphertext;

        public EncryptedURL(String base64Nonce, String base64Ciphertext) {
            this.base64Nonce = base64Nonce;
            this.base64Ciphertext = base64Ciphertext;
        }
    }

    @JsMethod
    public EncryptedURL encryptURL(String url) {
        // pad url to avoid leaking length
        while (url.length() % EncryptedURL.PAD_TO_SIZE != 0)
            url = url + " ";
        byte[] nonce = rootKey.createNonce();
        byte[] cipherText = rootKey.encrypt(url.getBytes(), nonce);
        Base64.Encoder encoder = Base64.getEncoder();
        return new EncryptedURL(encoder.encodeToString(nonce), encoder.encodeToString(cipherText));
    }

    @JsMethod
    public String decryptURL(String cipherTextBase64, String nonceBase64) {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] nonce = decoder.decode(nonceBase64);
        byte[] ciphertext = decoder.decode(cipherTextBase64);
        return new String(rootKey.decrypt(ciphertext, nonce)).trim();
    }

    /**
     *
     * @param friendName
     * @return a pair of the friends keys used to generate the fingerprint, and the resulting fingerprint
     */
    @JsMethod
    public CompletableFuture<Pair<List<PublicKeyHash>, FingerPrint>> generateFingerPrint(String friendName) {
        return getPublicKeyHashes(username)
                .thenCompose(ourKeys -> getPublicKeyHashes(friendName)
                        .thenApply(friendKeysPair -> {
                            PublicKeyHash friendId = friendKeysPair.left;
                            PublicKeyHash friendBox = friendKeysPair.right;
                            List<PublicKeyHash> friendKeys = Arrays.asList(friendId, friendBox);
                            return new Pair<>(friendKeys, FingerPrint.generate(
                                    username,
                                    Arrays.asList(ourKeys.left, ourKeys.right),
                                    friendName,
                                    friendKeys,
                                    crypto.hasher));
                        }));
    }

    @JsMethod
    public static CompletableFuture<UserContext> fromSecretLink(String link, NetworkAccess network, Crypto crypto) {
        AbsoluteCapability cap;
        try {
            cap = AbsoluteCapability.fromLink(link);
        } catch (Exception e) { //link was invalid
            CompletableFuture<UserContext> invalidLink = new CompletableFuture<>();
            invalidLink.completeExceptionally(e);
            return invalidLink;
        }
        WriterData empty = new WriterData(cap.owner,
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Collections.emptyMap(),
                        Optional.empty(),
                        Optional.empty());
        CommittedWriterData userData = new CommittedWriterData(MaybeMultihash.empty(), empty);
        UserContext context = new UserContext(null, null, null, null, network,
                crypto, userData, TrieNodeImpl.empty(), null, null);
        return buildTrieFromCap(cap, context.entrie, network, crypto)
                .thenApply(trieNode -> {
                    context.entrie = trieNode;
                    return context;
                });
    }

    private static CompletableFuture<TrieNode> buildTrieFromCap(AbsoluteCapability cap,
                                                                TrieNode currentRoot,
                                                                NetworkAccess network,
                                                                Crypto crypto) {
        EntryPoint entry = new EntryPoint(cap, "");
        return NetworkAccess.retrieveEntryPoint(entry, network)
                .thenCompose(r -> entry.isValid(r.getPath(), network).thenApply(valid -> {
                    if (! valid)
                        throw new IllegalStateException("Invalid link!");
                    return currentRoot.put(r.getPath(), entry);
                }));
    }

    public static CompletableFuture<AbsoluteCapability> getPublicCapability(Path originalPath, NetworkAccess network) {
        String ownerName = originalPath.getName(0).toString();

        return network.coreNode.getPublicKeyHash(ownerName).thenCompose(ownerOpt -> {
            if (!ownerOpt.isPresent())
                throw new IllegalStateException("Owner doesn't exist for path " + originalPath);
            PublicKeyHash owner = ownerOpt.get();
            return WriterData.getWriterData(owner, owner, network.mutable, network.dhtClient).thenCompose(userData -> {
                Optional<Multihash> publicData = userData.props.publicData;
                if (! publicData.isPresent())
                    throw new IllegalStateException("User " + ownerName + " has not made any files public.");

                return network.dhtClient.get(publicData.get())
                        .thenCompose(rootCbor -> InodeFileSystem.build(rootCbor.get(), network.hasher, network.dhtClient))
                        .thenCompose(publicCaps -> publicCaps.getByPath(originalPath.toString()))
                        .thenApply(resOpt -> {
                            if (resOpt.isEmpty() || resOpt.get().left.cap.isEmpty())
                                throw new IllegalStateException("User " + ownerName + " has not published a file at " + originalPath);
                            return resOpt.get().left.cap.get();
                        });
            });
        });
    }

    @JsMethod
    public CompletableFuture<Optional<FileWrapper>> getPublicFile(Path file) {
        FileProperties.ensureValidParsedPath(file);
        return getPublicCapability(file, network)
                .thenCompose(cap -> buildTrieFromCap(cap, TrieNodeImpl.empty(), network, crypto)
                .thenCompose(t -> t.getByPath(file.toString(), crypto.hasher, network)))
                .exceptionally(e -> Optional.empty());
    }

    @JsMethod
    public CompletableFuture<String> getEntryPath() {
        if (username != null)
            return CompletableFuture.completedFuture("/");

        CompletableFuture<Optional<FileWrapper>> dir = getByPath("/");
        return dir.thenCompose(opt -> getLinkPath(opt.get()))
                .thenApply(path -> path.substring(1)); // strip off extra slash at root
    }

    private CompletableFuture<String> getLinkPath(FileWrapper file) {
        if (!file.isDirectory())
            return CompletableFuture.completedFuture("");
        return file.getChildren(crypto.hasher, network)
                .thenCompose(children -> {
                    if (children.size() != 1)
                        return CompletableFuture.completedFuture(file.getName());
                    FileWrapper child = children.stream().findAny().get();
                    if (child.isReadable()) // case where a directory was shared with exactly one direct child
                        return CompletableFuture.completedFuture(file.getName() + (child.isDirectory() ?
                                "/" + child.getName() : ""));
                    return getLinkPath(child)
                            .thenApply(p -> file.getName() + (p.length() > 0 ? "/" + p : ""));
                });
    }

    private CompletableFuture<UserContext> init(Consumer<String> progressCallback) {
        progressCallback.accept("Retrieving Friends");
        return writeSynchronizer.getValue(signer.publicKeyHash, signer.publicKeyHash)
                .thenCompose(wd -> time(() -> createFileTree(entrie, username, network, crypto), "Creating filetree")
                        .thenApply(root -> {
                            this.entrie = root;
                            return this;
                        })
                );
    }

    public CompletableFuture<FileWrapper> getSharingFolder() {
        return getByPath("/" + username + "/shared").thenApply(opt -> opt.get());
    }

    /**
     *
     * @return The pending storage requests on the server we are talking to if we are an admin
     */
    @JsMethod
    public CompletableFuture<List<DecodedSpaceRequest>> getAndDecodePendingSpaceRequests() {
        return getPendingSpaceRequests().thenCompose(this::decodeSpaceRequests);
    }

    /**
     *
     * @return The pending storage requests on the server we are talking to if we are an admin
     */
    @JsMethod
    public CompletableFuture<List<SpaceUsage.LabelledSignedSpaceRequest>> getPendingSpaceRequests() {
        byte[] signedTime = TimeLimitedClient.signNow(signer.secret);
        return network.dhtClient.id()
                .thenCompose(id -> network.instanceAdmin.getPendingSpaceRequests(signer.publicKeyHash, id, signedTime));
    }

    /**
     *
     * @param in raw space requests
     * @return raw space requests paired with their decoded request
     */
    @JsMethod
    public CompletableFuture<List<DecodedSpaceRequest>> decodeSpaceRequests(List<QuotaControl.LabelledSignedSpaceRequest> in) {
        return DecodedSpaceRequest.decodeSpaceRequests(in, network.coreNode, network.dhtClient);
    }

    /**
     *
     * @param req
     * @return true when completed successfully
     */
    @JsMethod
    public CompletableFuture<Boolean> approveSpaceRequest(DecodedSpaceRequest req) {
        byte[] adminSignedRequest = signer.secret.signMessage(req.source.serialize());
        return network.dhtClient.id()
                .thenCompose(instanceId -> network.instanceAdmin
                        .approveSpaceRequest(signer.publicKeyHash, instanceId, adminSignedRequest));
    }

    /**
     *
     * @param req
     * @return true when completed successfully
     */
    @JsMethod
    public CompletableFuture<Boolean> rejectSpaceRequest(DecodedSpaceRequest req) {
        throw new IllegalStateException("Unimplemented!");
//        byte[] adminSignedRequest = signer.secret.signMessage(req.source.serialize());
//        return network.dhtClient.id()
//                .thenCompose(instanceId -> network.instanceAdmin
//                        .rejectSpaceRequest(signer.publicKeyHash, instanceId, adminSignedRequest));
    }

    @JsMethod
    public CompletableFuture<PaymentProperties> getPaymentProperties(boolean newClientSecret) {
        byte[] signedTime = TimeLimitedClient.signNow(signer.secret);
        return network.spaceUsage.getPaymentProperties(signer.publicKeyHash, newClientSecret, signedTime);
    }

    /**
     *
     * @return The maximum amount of space this user is allowed to use in bytes
     */
    @JsMethod
    public CompletableFuture<Long> getQuota() {
        byte[] signedTime = TimeLimitedClient.signNow(signer.secret);
        return network.spaceUsage.getQuota(signer.publicKeyHash, signedTime);
    }

    /**
     *
     * @return The total amount of space used by this account in bytes
     */
    @JsMethod
    public CompletableFuture<Long> getSpaceUsage() {
        return network.spaceUsage.getUsage(signer.publicKeyHash);
    }

    /**
     *
     * @return true when completed successfully
     */
    @JsMethod
    public CompletableFuture<Boolean> requestSpace(long requestedQuota) {
        return network.spaceUsage.requestQuota(username, signer, requestedQuota);
    }

    @JsMethod
    public CompletableFuture<Boolean> isRegistered() {
        LOG.info("isRegistered");
        return network.coreNode.getUsername(signer.publicKeyHash).thenApply(registeredUsername -> {
            LOG.info("got username \"" + registeredUsername + "\"");
            return this.username.equals(registeredUsername);
        });
    }

    @JsMethod
    public CompletableFuture<Boolean> isAvailable() {
        return network.coreNode.getPublicKeyHash(username)
                .thenApply(publicKey -> !publicKey.isPresent());
    }

    public CompletableFuture<LocalDate> getUsernameClaimExpiry() {
        return network.coreNode.getChain(username)
                .thenApply(chain -> chain.get(chain.size() - 1).claim.expiry);
    }

    public CompletableFuture<Boolean> usernameIsExpired() {
        return network.coreNode.getChain(username)
                .thenApply(chain -> UserPublicKeyLink.isExpiredClaim(chain.get(chain.size() - 1)));
    }

    public CompletableFuture<Boolean> renewUsernameClaim(LocalDate expiry) {
        return renewUsernameClaim(username, signer, expiry, crypto.hasher, network);
    }

    private static CompletableFuture<Boolean> signupWithRetry(String username,
                                                              UserPublicKeyLink chain,
                                                              String token,
                                                              OpLog operations,
                                                              Hasher hasher,
                                                              NetworkAccess network,
                                                              Consumer<String> progressCallback) {
        byte[] data = new CborObject.CborList(Arrays.asList(chain)).serialize();
        return time(() -> hasher.generateProofOfWork(ProofOfWork.MIN_DIFFICULTY, data), "Proof of work")
                .thenCompose(proof -> network.coreNode.signup(username, chain, operations, proof, token))
                .thenCompose(diff -> {
                    if (diff.isPresent()) {
                        progressCallback.accept("The server is currently under load, retrying...");
                        return time(() -> hasher.generateProofOfWork(diff.get().requiredDifficulty, data), "Proof of work")
                                .thenCompose(proof -> network.coreNode.signup(username, chain, operations, proof, token))
                                .thenApply(d -> {
                                    if (d.isPresent())
                                        throw new IllegalStateException("Server is under load please try again later");
                                    return true;
                                });
                    }
                    return Futures.of(true);
                });
    }

    private static CompletableFuture<Boolean> updateChainWithRetry(String username,
                                                                   List<UserPublicKeyLink> claimChain,
                                                                   String token,
                                                                   Hasher hasher,
                                                                   NetworkAccess network,
                                                                   Consumer<String> progressCallback) {
        byte[] data = new CborObject.CborList(claimChain).serialize();
        return time(() -> hasher.generateProofOfWork(ProofOfWork.MIN_DIFFICULTY, data), "Proof of work")
                .thenCompose(proof -> network.coreNode.updateChain(username, claimChain, proof, token))
                .thenCompose(diff -> {
                    if (diff.isPresent()) {
                        progressCallback.accept("The server is currently under load, retrying...");
                        return time(() -> hasher.generateProofOfWork(diff.get().requiredDifficulty, data), "Proof of work")
                                .thenCompose(proof -> network.coreNode.updateChain(username, claimChain, proof, token))
                                .thenApply(d -> {
                                    if (d.isPresent())
                                        throw new IllegalStateException("Server is under load please try again later");
                                    return true;
                                });
                    }
                    return Futures.of(true);
                });
    }

    public static CompletableFuture<Boolean> renewUsernameClaim(String username,
                                                                SigningPrivateKeyAndPublicHash signer,
                                                                LocalDate expiry,
                                                                Hasher hasher,
                                                                NetworkAccess network) {
        LOG.info("renewing username: " + username + " with expiry " + expiry);
        return network.coreNode.getChain(username).thenCompose(existing -> {
            UserPublicKeyLink last = existing.get(existing.size() - 1);
            List<Multihash> storage = last.claim.storageProviders;
            UserPublicKeyLink.Claim newClaim = UserPublicKeyLink.Claim.build(username, signer.secret, expiry, storage);
            List<UserPublicKeyLink> updated = new ArrayList<>(existing.subList(0, existing.size() - 1));
            updated.add(new UserPublicKeyLink(signer.publicKeyHash, newClaim, Optional.empty()));
            return updateChainWithRetry(username, updated, "", hasher, network, x -> {});
        });
    }

    @JsMethod
    public CompletableFuture<Pair<Integer, Integer>> getTotalSpaceUsedJS(PublicKeyHash owner) {
        return getTotalSpaceUsed(owner, owner)
                .thenApply(size -> new Pair<>((int) (size >> 32), size.intValue()));
    }

    public CompletableFuture<Long> getTotalSpaceUsed() {
        return getTotalSpaceUsed(signer.publicKeyHash, signer.publicKeyHash);
    }

    public CompletableFuture<Long> getTotalSpaceUsed(PublicKeyHash ownerHash, PublicKeyHash writerHash) {
        // assume no cycles in owned keys
        return WriterData.getOwnedKeysRecursive(ownerHash, writerHash, network.mutable, network.dhtClient, network.hasher)
                .thenCompose(allOwned -> Futures.reduceAll(allOwned.stream()
                                .map(w -> network.mutable.getPointerTarget(ownerHash, w, network.dhtClient)
                                        .thenCompose(root -> root.isPresent() ?
                                                network.dhtClient.getRecursiveBlockSize(root.get()) :
                                                CompletableFuture.completedFuture(0L)))
                                .collect(Collectors.toList()),
                        0L, (t, fut) -> fut.thenApply(x -> x + t), (a, b) -> a + b));
    }

    public CompletableFuture<SecretGenerationAlgorithm> getKeyGenAlgorithm() {
        return getWriterData(network, signer.publicKeyHash, signer.publicKeyHash)
                .thenApply(wd -> wd.props.generationAlgorithm
                        .orElseThrow(() -> new IllegalStateException("No login algorithm specified in user data!")));
    }

    public CompletableFuture<Optional<PublicKeyHash>> getNamedKey(String name) {
        return getWriterData(network, signer.publicKeyHash, signer.publicKeyHash)
                .thenApply(wd -> wd.props.namedOwnedKeys.get(name))
                .thenApply(res -> Optional.ofNullable(res).map(p -> p.ownedKey));
    }

    @JsMethod
    public CompletableFuture<UserContext> changePassword(String oldPassword, String newPassword) {
        return getKeyGenAlgorithm().thenCompose(alg -> {
            // Use a new salt, and if this is a legacy account with generated boxer, remove it from generation
            SecretGenerationAlgorithm newAlgorithm = SecretGenerationAlgorithm.withNewSalt(alg, crypto.random).withoutBoxer();
            // set claim expiry to two months from now
            return changePassword(oldPassword, newPassword, alg, newAlgorithm, LocalDate.now().plusMonths(2));
        });
    }

    public CompletableFuture<UserContext> changePassword(String oldPassword,
                                                         String newPassword,
                                                         SecretGenerationAlgorithm existingAlgorithm,
                                                         SecretGenerationAlgorithm newAlgorithm,
                                                         LocalDate expiry) {
        LOG.info("Changing password and setting expiry to: " + expiry);

        return UserUtil.generateUser(username, oldPassword, crypto.hasher, crypto.symmetricProvider, crypto.random, crypto.signer, crypto.boxer, existingAlgorithm)
                .thenCompose(existingUser -> {
                    if (!existingUser.getUser().secretSigningKey.equals(this.signer.secret))
                        throw new IllegalArgumentException("Incorrect existing password during change password attempt!");
                    return UserUtil.generateUser(username, newPassword, crypto.hasher, crypto.symmetricProvider,
                            crypto.random, crypto.signer, crypto.boxer, newAlgorithm)
                            .thenCompose(updatedUser -> {
                                PublicSigningKey newPublicSigningKey = updatedUser.getUser().publicSigningKey;
                                PublicKeyHash existingOwner = ContentAddressedStorage.hashKey(existingUser.getUser().publicSigningKey);

                                BoxingKeyPair newBoxingKeypair = newAlgorithm.includesBoxerGeneration() ? updatedUser.getBoxingPair() : boxer;
                                return IpfsTransaction.call(existingOwner,
                                        tid -> network.dhtClient.putSigningKey(
                                                existingUser.getUser().secretSigningKey.signMessage(newPublicSigningKey.serialize()),
                                                existingOwner,
                                                newPublicSigningKey,
                                                tid),
                                        network.dhtClient
                                ).thenCompose(newSignerHash -> {
                                    SigningPrivateKeyAndPublicHash newSigner =
                                            new SigningPrivateKeyAndPublicHash(newSignerHash, updatedUser.getUser().secretSigningKey);
                                    Map<PublicKeyHash, SigningPrivateKeyAndPublicHash> ownedKeys = new HashMap<>();
                                    return getUserRoot().thenCompose(homeDir -> {
                                        // If we ever implement plausibly deniable dual (N) login this will need to include all the other keys
                                        ownedKeys.put(homeDir.writer(), homeDir.signingPair());
                                        // Add any named owned key to lookup as well
                                        // TODO need to get the pki keypair here if were are the 'peergos' user

                                        // auth new key by adding to existing writer data first
                                        OwnerProof proof = OwnerProof.build(newSigner, signer.publicKeyHash);
                                        return writeSynchronizer.applyUpdate(signer.publicKeyHash, signer, (wd, tid) ->
                                                wd.addOwnedKey(signer.publicKeyHash, signer, proof, network.dhtClient, network.hasher))
                                                .thenCompose(version -> version.get(signer).props.changeKeys(signer,
                                                        newSigner,
                                                        newBoxingKeypair,
                                                        existingUser.getRoot(),
                                                        updatedUser.getRoot(),
                                                        newAlgorithm,
                                                        ownedKeys,
                                                        network)).thenCompose(writerData -> {
                                                    SigningPrivateKeyAndPublicHash newUser =
                                                            new SigningPrivateKeyAndPublicHash(newSignerHash, updatedUser.getUser().secretSigningKey);
                                                    return network.coreNode.getChain(username).thenCompose(existing -> {
                                                        List<Multihash> storage = existing.get(existing.size() - 1).claim.storageProviders;
                                                        List<UserPublicKeyLink> claimChain = UserPublicKeyLink.createChain(signer, newUser, username, expiry, storage);
                                                        return updateChainWithRetry(username, claimChain, "", crypto.hasher, network, x -> {})
                                                                .thenCompose(updatedChain -> {
                                                                    if (!updatedChain)
                                                                        throw new IllegalStateException("Couldn't register new public keys during password change!");

                                                                    return UserContext.signIn(username, newPassword, network, crypto);
                                                                });
                                                    });
                                                });
                                    });
                                });
                            });
                });
    }

    private static CompletableFuture<TrieNode> createEntryDirectory(SigningPrivateKeyAndPublicHash owner,
                                                                    String directoryName,
                                                                    SymmetricKey userRootKey,
                                                                    NetworkAccess network,
                                                                    Crypto crypto) {
        long t1 = System.currentTimeMillis();
        SigningKeyPair writer = SigningKeyPair.random(crypto.random, crypto.signer);
        LOG.info("Random User generation took " + (System.currentTimeMillis() - t1) + " mS");
        // Steps (All in 1 transaction):
        // 1. Add signing key authorised by owner
        // 2. Commit authorisation for writer to owner WriterData
        // 3. Add empty WriterData for writer
        // 4. Add root directory writer's WriterData
        // 5. Add entry point to root dir to owner WriterData

        byte[] rootMapKey = crypto.random.randomBytes(32); // root will be stored under this label
        SymmetricKey rootRKey = SymmetricKey.random();
        SymmetricKey rootWKey = SymmetricKey.random();
        LOG.info("Random keys generation took " + (System.currentTimeMillis() - t1) + " mS");

        PublicKeyHash preHash = ContentAddressedStorage.hashKey(writer.publicSigningKey);
        SigningPrivateKeyAndPublicHash writerPair =
                new SigningPrivateKeyAndPublicHash(preHash, writer.secretSigningKey);
        WritableAbsoluteCapability rootPointer =
                new WritableAbsoluteCapability(owner.publicKeyHash, preHash, rootMapKey, rootRKey, rootWKey);
        EntryPoint entry = new EntryPoint(rootPointer, directoryName);
        return IpfsTransaction.call(owner.publicKeyHash, tid -> network.dhtClient.putSigningKey(
                owner.secret.signMessage(writer.publicSigningKey.serialize()),
                owner.publicKeyHash,
                writer.publicSigningKey,
                tid).thenCompose(writerHash -> {

            // and authorise the writer key
            return network.synchronizer.applyComplexUpdate(owner.publicKeyHash, owner,
                    (s, committer) -> s.get(owner.publicKeyHash).props.addOwnedKeyAndCommit(owner.publicKeyHash, owner,
                            OwnerProof.build(writerPair, owner.publicKeyHash), s.get(owner.publicKeyHash).hash, network, tid)
                            .thenCompose(s2 -> {
                                long t2 = System.currentTimeMillis();
                                RelativeCapability nextChunk =
                                        RelativeCapability.buildSubsequentChunk(crypto.random.randomBytes(32), rootRKey);
                                return CryptreeNode.createEmptyDir(MaybeMultihash.empty(), rootRKey, rootWKey, Optional.of(writerPair),
                                                new FileProperties(directoryName, true, false, "", 0, LocalDateTime.now(),
                                                        false, Optional.empty(), Optional.empty()),
                                                Optional.empty(), SymmetricKey.random(), nextChunk, crypto.hasher)
                                        .thenCompose(root -> {
                                            LOG.info("Uploading entry point directory");
                                            return WriterData.createEmpty(owner.publicKeyHash, writerPair,
                                                    network.dhtClient, network.hasher, tid)
                                                    .thenCompose(empty -> empty.commit(owner.publicKeyHash, writerPair, MaybeMultihash.empty(), network, tid))
                                                    .thenCompose(s3 -> root.commit(s3, committer, rootPointer, Optional.of(writerPair), network, tid)
                                                            .thenApply(finalSnapshot -> {
                                                                long t3 = System.currentTimeMillis();
                                                                LOG.info("Uploading root dir metadata took " + (t3 - t2) + " mS");
                                                                return finalSnapshot;
                                                            }))
                                                    .thenCompose(x -> addRootEntryPointAndCommit(x.merge(s2), entry, owner, userRootKey, network, tid));
                                        });
                            }));
        }), network.dhtClient).thenApply(s -> TrieNodeImpl.empty().put("/" + directoryName, entry));
    }

    public CompletableFuture<PublicSigningKey> getSigningKey(PublicKeyHash keyhash) {
        return network.dhtClient.get(keyhash).thenApply(cborOpt -> cborOpt.map(PublicSigningKey::fromCbor).get());
    }

    public CompletableFuture<PublicBoxingKey> getBoxingKey(PublicKeyHash keyhash) {
        return network.dhtClient.get(keyhash).thenApply(cborOpt -> cborOpt.map(PublicBoxingKey::fromCbor).get());
    }

    /**
     *
     * @param username
     * @return A pair containing the identity key hash and the boxing key hash of the user
     */
    public CompletableFuture<Pair<PublicKeyHash, PublicKeyHash>> getPublicKeyHashes(String username) {
        return network.coreNode.getPublicKeyHash(username)
                .thenCompose(signerOpt -> {
                    if (! signerOpt.isPresent())
                        throw new IllegalStateException("Couldn't retrieve identity key for " + username);
                    return getSigningKey(signerOpt.get())
                            .thenCompose(signer2 -> getWriterData(network, signerOpt.get(), signerOpt.get())
                                    .thenApply(wd -> new Pair<>(signerOpt.get(), wd.props.followRequestReceiver.get())));
                });
    }

    public CompletableFuture<Optional<Pair<PublicKeyHash, PublicBoxingKey>>> getPublicKeys(String username) {
        return network.coreNode.getPublicKeyHash(username)
                .thenCompose(signerOpt ->
                        signerOpt.map(signer -> getSigningKey(signer)
                                .thenCompose(signer2 -> getWriterData(network, signerOpt.get(), signerOpt.get())
                                        .thenCompose(wd -> getBoxingKey(wd.props.followRequestReceiver.get())
                                                .thenApply(boxer -> Optional.of(new Pair<>(signerOpt.get(), boxer))))))
                                .orElse(CompletableFuture.completedFuture(Optional.empty())));
    }

    private CompletableFuture<CommittedWriterData> addOwnedKeyAndCommit(SigningPrivateKeyAndPublicHash owned) {
        return writeSynchronizer.applyUpdate(signer.publicKeyHash, signer,
                (wd, tid) -> wd.addOwnedKey(signer.publicKeyHash, signer,
                        OwnerProof.build(owned, signer.publicKeyHash), network.dhtClient, network.hasher))
                .thenApply(v -> v.get(signer));
    }

    public CompletableFuture<CommittedWriterData> addNamedOwnedKeyAndCommit(String keyName,
                                                                            SigningPrivateKeyAndPublicHash owned) {
        return writeSynchronizer.applyUpdate(signer.publicKeyHash, signer,
                (wd, tid) -> CompletableFuture.completedFuture(wd.addNamedKey(keyName, OwnerProof.build(owned, signer.publicKeyHash))))
                .thenApply(v -> v.get(signer));
    }

    @JsMethod
    public CompletableFuture<Boolean> deleteAccount(String password) {
        return signIn(username, password, network, crypto)
                .thenCompose(user -> {
                    // set mutable pointer of root dir writer and owner to EMPTY
                    SigningPrivateKeyAndPublicHash identity = user.signer;
                    PublicKeyHash owner = identity.publicKeyHash;
                    return user.getUserRoot().thenCompose(root -> {
                        SigningPrivateKeyAndPublicHash pair = root.signingPair();
                        CommittedWriterData current = root.getVersionRoot();
                        HashCasPair cas = new HashCasPair(current.hash, MaybeMultihash.empty());
                        byte[] signed = pair.secret.signMessage(cas.serialize());
                        return network.mutable.setPointer(this.signer.publicKeyHash, pair.publicKeyHash, signed);
                    }).thenCompose(x -> network.spaceUsage.requestQuota(username, identity, 1024*1024))
                            .thenCompose(x -> network.mutable.getPointerTarget(owner, owner, network.dhtClient)
                                    .thenCompose(current -> {
                                        HashCasPair cas = new HashCasPair(current, MaybeMultihash.empty());
                                        byte[] signed = identity.secret.signMessage(cas.serialize());
                                        return network.mutable.setPointer(owner, owner, signed);
                                    })
                            );
                });
    }

    public CompletableFuture<Boolean> unPublishFile(Path path) {
        return sharedWith(path).thenCompose(sharedWithState -> getByPath(path)
                .thenCompose(opt -> {
                    FileWrapper toUnshare = opt.get();
                    return getByPath(path.getParent())
                            .thenCompose(parentOpt -> {
                                FileWrapper parent = parentOpt.get();
                                return removePublicCap(path.toString()).thenCompose(cwd -> rotateAllKeys(toUnshare, parent, false)
                                        .thenCompose(markedDirty ->
                                                sharedWithCache.removeSharedWith(SharedWithCache.Access.READ, path, sharedWithState.readAccess)
                                                        .thenCompose(b ->
                                                                sharedWithCache.removeSharedWith(SharedWithCache.Access.WRITE, path, sharedWithState.writeAccess))
                                        ));
                            }).thenApply(res -> true);
                }));
    }

    private CompletableFuture<CommittedWriterData> removePublicCap(String path) {
        return writeSynchronizer.applyUpdate(signer.publicKeyHash, signer, (wd, tid) -> {
            Optional<Multihash> publicData = wd.publicData;
            if (publicData.isEmpty())
                return Futures.of(wd);
            return network.dhtClient.get(publicData.get())
                    .thenCompose(rootCbor -> InodeFileSystem.build(rootCbor.get(), crypto.hasher, network.dhtClient))
                    .thenCompose(pubCaps -> pubCaps.removeCap(signer.publicKeyHash, signer, path, tid))
                    .thenCompose(updated -> network.dhtClient.put(signer.publicKeyHash, signer, updated.serialize(), crypto.hasher, tid))
                    .thenApply(newRoot -> wd.withPublicRoot(newRoot));
        }).thenApply(v -> v.get(signer));
    }

    public CompletableFuture<CommittedWriterData> makePublic(FileWrapper file) {
        if (! file.getOwnerName().equals(username))
            return Futures.errored(new IllegalStateException("Only the owner of a file can make it public!"));
        if (file.isUserRoot())
            return Futures.errored(new IllegalStateException("You cannot publish your home directory!"));
        return writeSynchronizer.applyUpdate(signer.publicKeyHash, signer, (wd, tid) -> file.getPath(network).thenCompose(path -> {
            ensureAllowedToShare(file, username, false);
            Optional<Multihash> publicData = wd.publicData;

            CompletableFuture<InodeFileSystem> publicCaps = publicData.isPresent() ?
                    network.dhtClient.get(publicData.get())
                            .thenCompose(rootCbor -> InodeFileSystem.build(rootCbor.get(), crypto.hasher, network.dhtClient)) :
                    InodeFileSystem.createEmpty(signer.publicKeyHash, signer, network.dhtClient, crypto.hasher, tid);

            AbsoluteCapability cap = file.getPointer().capability.readOnly();
            return publicCaps.thenCompose(pubCaps -> pubCaps.addCap(signer.publicKeyHash, signer, path, cap, tid))
                    .thenCompose(updated -> network.dhtClient.put(signer.publicKeyHash, signer, updated.serialize(), crypto.hasher, tid))
                    .thenApply(newRoot -> wd.withPublicRoot(newRoot));
        })).thenApply(v -> v.get(signer));
    }

    private static void ensureAllowedToShare(FileWrapper file, String ourname, boolean isWrite) {
        if (file.isUserRoot())
            throw new IllegalStateException("You cannot share your home directory public!");
        if (isWrite && ! file.getOwnerName().equals(ourname))
            throw new IllegalStateException("Only the owner of a file can grant write access!");
    }

    @JsMethod
    public CompletableFuture<Set<FileWrapper>> getFriendRoots() {
        return getChildren("/").thenApply(c -> c.stream()
                .filter(f -> ! f.getName().equals(username))
                .collect(Collectors.toSet()));
    }

    @JsMethod
    public CompletableFuture<Set<String>> getFollowing() {
        return getFriendRoots()
                .thenApply(set -> set.stream()
                        .map(FileWrapper::getOwnerName)
                        .collect(Collectors.toSet()));
    }

    @JsMethod
    public CompletableFuture<Set<String>> getFollowerNames() {
        return getFollowerRoots(true).thenApply(Map::keySet);
    }

    public CompletableFuture<Map<String, FileWrapper>> getFollowerRoots(boolean filterPending) {
        return (filterPending ?
                getPendingOutgoingFollowRequests()
                        .thenApply(p -> p.pendingOutgoingFollowRequests)
                : Futures.of(Collections.<String>emptySet()))
                .thenCompose(pendingOutgoing -> getFollowerRoots(pendingOutgoing));
    }

    private CompletableFuture<Map<String, FileWrapper>> getFollowerRoots(Set<String> pendingOutgoing) {
        return getSharingFolder()
                .thenCompose(sharing -> sharing.getChildren(crypto.hasher, network))
                .thenApply(children -> children.stream()
                        .filter(c -> ! c.getName().startsWith(".") &&
                                ! c.getName().startsWith(GROUPS_FILENAME) &&
                                ! pendingOutgoing.contains(c.getName()))
                        .collect(Collectors.toMap(e -> e.getFileProperties().name, e -> e)));
    }

    public CompletableFuture<Set<FriendSourcedTrieNode>> getFollowingNodes() {
        return Futures.of(entrie.getChildNodes()
                .stream()
                .filter(n -> n instanceof FriendSourcedTrieNode)
                .map(n -> (FriendSourcedTrieNode)n)
                .filter(n -> ! n.ownerName.equals(username))
                .collect(Collectors.toSet()));
    }

    public CompletableFuture<Map<String, FriendAnnotation>> getFriendAnnotations() {
        return getUserRoot()
                .thenCompose(home -> home.hasChild(FRIEND_ANNOTATIONS_FILE_NAME, crypto.hasher, network)
                        .thenCompose(exists ->  {
                            if (! exists)
                                return CompletableFuture.completedFuture(Collections.emptyMap());
                            Map<String, FriendAnnotation> res = new TreeMap<>();
                            return home.getChild(FRIEND_ANNOTATIONS_FILE_NAME, crypto.hasher, network)
                                    .thenCompose(fileOpt ->
                                            fileOpt.get().getInputStream(network, crypto, x -> {})
                                    .thenCompose(reader -> reader.parseStream(FriendAnnotation::fromCbor,
                                            anno -> res.put(anno.getUsername(), anno),
                                            fileOpt.get().getSize())))
                                    .thenApply(x -> res);
                        }));
    }

    @JsMethod
    public CompletableFuture<Boolean> addFriendAnnotation(FriendAnnotation annotation) {
        return getFriendAnnotations().thenCompose(existing -> {
            Map<String, FriendAnnotation> updated = new TreeMap<>(existing);
            updated.put(annotation.getUsername(), annotation);
            List<FriendAnnotation> values = updated.values()
                    .stream()
                    .collect(Collectors.toList());
            ByteArrayOutputStream serialized = new ByteArrayOutputStream();
            for (FriendAnnotation value : values) {
                try {
                    serialized.write(value.serialize());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return getUserRoot().thenCompose(home -> home.uploadFileSection(
                                    FRIEND_ANNOTATIONS_FILE_NAME,
                                    AsyncReader.build(serialized.toByteArray()),
                                    true,
                                    0,
                                    serialized.size(),
                                    Optional.empty(),
                                    true,
                                    network,
                                    crypto,
                                    x -> {},
                                    crypto.random.randomBytes(32)))
                    .thenApply(x -> true);
        });
    }

    public CompletableFuture<Groups> getGroupNameMappings() {
        return FileUtils.getOrCreateObject(this,
                Paths.get(username, SHARED_DIR_NAME, GROUPS_FILENAME),
                () -> Groups.generate(crypto.random),
                this::initialiseGroups,
                Cborable.parser(Groups::fromCbor));
    }

    private CompletableFuture<Set<String>> getFriendNames() {
        return getFriendRoots()
                .thenApply(dirs -> dirs.stream()
                        .map(FileWrapper::getName)
                        .collect(Collectors.toSet()));
    }

    private CompletableFuture<Boolean> initialiseGroups(Groups g) {
        return getFollowerNames().thenCompose(followers -> getFriendNames()
                .thenCompose(friends -> {
                    return Futures.reduceAll(g.uidToGroupName.entrySet(), true,
                            (b, e) -> getUserRoot()
                                    .thenCompose(home -> home.getOrMkdirs(Paths.get(SHARED_DIR_NAME, e.getKey()), network, true, crypto))
                                    .thenCompose(x -> shareReadAccessWith(Paths.get(username, SHARED_DIR_NAME, e.getKey()),
                                            e.getValue().equals(SocialState.FOLLOWERS_GROUP_NAME) ? followers : friends))
                                    .thenApply(x -> true),
                            (a, b) -> a && b);
                }));
    }

    private CompletableFuture<PendingSocialState> getPendingOutgoingFollowRequests() {
        return getUserRoot()
                .thenCompose(home -> home.hasChild(SOCIAL_STATE_FILENAME, crypto.hasher, network)
                        .thenCompose(exists ->  {
                            if (! exists)
                                return CompletableFuture.completedFuture(PendingSocialState.empty());
                            return home.getChild(SOCIAL_STATE_FILENAME, crypto.hasher, network)
                                    .thenCompose(fileOpt ->
                                            fileOpt.get().getInputStream(network, crypto, x -> {})
                                                    .thenCompose(reader -> Serialize.parse(reader, fileOpt.get().getSize(),
                                                            PendingSocialState::fromCbor)));
                        }));
    }

    private CompletableFuture<Boolean> removeFromPendingOutgoing(String usernameToRemove) {
        return getUserRoot()
                .thenCompose(home -> home.hasChild(SOCIAL_STATE_FILENAME, crypto.hasher, network)
                        .thenCompose(exists ->  {
                            if (! exists)
                                return CompletableFuture.completedFuture(true);
                            return home.getChild(SOCIAL_STATE_FILENAME, crypto.hasher, network)
                                    .thenCompose(fileOpt ->
                                            fileOpt.get().getInputStream(network, crypto, x -> {})
                                                    .thenCompose(reader -> Serialize.parse(reader, fileOpt.get().getSize(),
                                                            PendingSocialState::fromCbor))
                                                    .thenCompose(current -> {
                                                        PendingSocialState updated = current.withoutPending(usernameToRemove);
                                                        byte[] raw = updated.serialize();
                                                        return fileOpt.get().overwriteFile(AsyncReader.build(raw), raw.length,
                                                                network, crypto, x -> {})
                                                                .thenApply(x -> true);
                                                    }));
                        }));
    }

    @JsMethod
    public CompletableFuture<SocialState> getSocialState() {
        return processFollowRequests()
                .thenCompose(pendingIncoming -> getPendingOutgoingFollowRequests()
                        .thenCompose(pendingOutgoing -> getFollowerRoots(pendingOutgoing.pendingOutgoingFollowRequests)
                                .thenCompose(followerRoots -> getFriendRoots().thenCompose(
                                        followingRoots -> getFollowerNames().thenCompose(
                                                followers -> getFriendAnnotations().thenCompose(
                                                        annotations -> getGroupNameMappings().thenApply(
                                                                groups -> new SocialState(pendingIncoming,
                                                                        pendingOutgoing.pendingOutgoingFollowRequests,
                                                                        followers, followerRoots, followingRoots,
                                                                        annotations, groups.uidToGroupName))))))));
    }

    @JsMethod
    public CompletableFuture<Boolean> sendInitialFollowRequest(String targetUsername) {
        if (username.equals(targetUsername)) {
            return CompletableFuture.completedFuture(false);
        }
        return sendFollowRequest(targetUsername, SymmetricKey.random());
    }

    @JsMethod
    public CompletableFuture<Boolean> sendInitialFollowRequests(String[] targetUsernames) {
        Set<String> usernames = new HashSet<>(Arrays.asList(targetUsernames));
        return Futures.reduceAll(usernames,
                true,
                (b, targetUsername) -> sendFollowRequest(targetUsername, SymmetricKey.random()),
                (a, b) -> a);
    }

    @JsMethod
    public CompletableFuture<Boolean> sendReplyFollowRequest(FollowRequestWithCipherText initialRequestAndRaw, boolean accept, boolean reciprocate) {
        FollowRequest initialRequest = initialRequestAndRaw.req;
        String theirUsername = initialRequest.entry.get().ownerName;
        // if accept, create directory to share with them, note in entry points (they follow us)
        if (!accept && !reciprocate) {
            // send a null entry and absent key (full rejection)
            // write a null entry point and tell them we're not reciprocating with an absent key
            EntryPoint entry = new EntryPoint(AbsoluteCapability.createNull(), username);
            FollowRequest reply = new FollowRequest(Optional.of(entry), Optional.empty());

            return getPublicKeys(initialRequest.entry.get().ownerName).thenCompose(pair -> {
                PublicBoxingKey targetUser = pair.get().right;

                return blindAndSendFollowRequest(initialRequest.entry.get().pointer.owner, targetUser, reply)
                        .thenCompose(b ->
                                // remove pending follow request from them
                                network.social.removeFollowRequest(signer.publicKeyHash, signer.secret.signMessage(initialRequestAndRaw.cipher.serialize()))
                        );
            });
        }

        return CompletableFuture.completedFuture(true).thenCompose(b -> {
            if (accept) {
                return getSharingFolder().thenCompose(sharing -> sharing.getChild(theirUsername, crypto.hasher, network)
                        .thenCompose(existingOpt -> {
                            if (existingOpt.isPresent())
                                return Futures.of(existingOpt);
                            return sharing.getChild(theirUsername, crypto.hasher, network)
                                    .thenCompose(existingFriendDir -> {
                                        if (existingFriendDir.isEmpty())
                                            return sharing.mkdir(theirUsername, network, initialRequest.key.get(), true, crypto)
                                                    .thenCompose(updatedSharing -> updatedSharing.getChild(theirUsername, crypto.hasher, network));
                                        // If we already have a sharing dir for them, don't rotate the keys
                                        return Futures.of(existingFriendDir);
                                    });
                        }).thenCompose(friendRootOpt -> {
                            FileWrapper friendRoot = friendRootOpt.get();
                            // add a note to our entry point store so we know who we sent the read access to
                            EntryPoint entry = new EntryPoint(friendRoot.getPointer().capability.readOnly(),
                                    username);
                            // add them to our followers group
                            return getGroupUid(SocialState.FOLLOWERS_GROUP_NAME)
                                    .thenCompose(followersUidOpt -> shareReadAccessWith(Paths.get(username,
                                            SHARED_DIR_NAME, followersUidOpt.get()), Collections.singleton(theirUsername)))
                                    .thenApply(x -> entry);
                        }));
            } else {
                EntryPoint entry = new EntryPoint(AbsoluteCapability.createNull(), username);
                return CompletableFuture.completedFuture(entry);
            }
        }).thenCompose(entry -> {

            Optional<SymmetricKey> baseKey;
            if (!reciprocate) {
                baseKey = Optional.empty(); // tell them we're not reciprocating
            } else {
                // if reciprocate, add entry point to their shared directory (we follow them) and then
                baseKey = Optional.of(initialRequest.entry.get().pointer.rBaseKey); // tell them we are reciprocating
            }
            FollowRequest reply = new FollowRequest(Optional.of(entry), baseKey);

            return (accept && reciprocate ?
                    getGroupUid(SocialState.FRIENDS_GROUP_NAME)
                            .thenCompose(friendsUidOpt -> shareReadAccessWith(Paths.get(username,
                                    SHARED_DIR_NAME, friendsUidOpt.get()), Collections.singleton(theirUsername))): // put them in our friends group
                    Futures.of(true))
                    .thenCompose(x -> getPublicKeys(initialRequest.entry.get().ownerName))
                    .thenCompose(pair -> {
                        PublicBoxingKey targetUser = pair.get().right;
                        return blindAndSendFollowRequest(initialRequest.entry.get().pointer.owner, targetUser, reply);
                    });
        }).thenCompose(b -> {
            if (reciprocate)
                return addExternalEntryPoint(initialRequest.entry.get())
                        .thenCompose(x -> retrieveAndAddEntryPointToTrie(entrie, initialRequest.entry.get()));
            return CompletableFuture.completedFuture(entrie);
        }).thenCompose(trie -> {
            // remove original request
            entrie = trie;
            return network.social.removeFollowRequest(signer.publicKeyHash, signer.secret.signMessage(initialRequestAndRaw.cipher.serialize()));
        });
    }

    /**
     * Send details to allow friend to follow us, and optionally let us follow them
     * create a tmp keypair whose public key we can prepend to the request without leaking information
     *
     * @param targetIdentity
     * @param targetBoxer
     * @param req
     * @return
     */
    private CompletableFuture<Boolean> blindAndSendFollowRequest(PublicKeyHash targetIdentity, PublicBoxingKey targetBoxer, FollowRequest req) {
        BlindFollowRequest blindRequest = BlindFollowRequest.build(targetBoxer, req, crypto.random, crypto.boxer);
        return network.social.sendFollowRequest(targetIdentity, blindRequest.serialize());
    }

    public CompletableFuture<Boolean> sendFollowRequest(String targetUsername, SymmetricKey requestedKey) {
        return getSharingFolder().thenCompose(sharing -> {
            // check for them not reciprocating
            return getFollowing().thenCompose(following -> {
                boolean alreadyFollowing = following.stream()
                        .filter(x -> x.equals(targetUsername))
                        .findAny()
                        .isPresent();
                if (alreadyFollowing) {
                    return Futures.errored(new Exception("User " + targetUsername +" is already a follower!"));
                }
                return getPublicKeys(targetUsername).thenCompose(targetUserOpt -> {
                    if (! targetUserOpt.isPresent()) {
                        return Futures.errored(new Exception("User " + targetUsername + " does not exist!"));
                    }
                    PublicBoxingKey targetUser = targetUserOpt.get().right;
                    return sharing.getOrMkdirs(Paths.get(targetUsername), network, true, crypto)
                            .thenCompose(friendRoot -> {

                                EntryPoint entry = new EntryPoint(friendRoot.getPointer().capability.readOnly(), username);
                                FollowRequest followReq = new FollowRequest(Optional.of(entry), Optional.ofNullable(requestedKey));

                                PublicKeyHash targetSigner = targetUserOpt.get().left;
                                return getPendingOutgoingFollowRequests()
                                        .thenCompose(pending -> blindAndSendFollowRequest(targetSigner, targetUser, followReq)
                                                .thenCompose(b -> {
                                                    // note that we have a pending request sent to them
                                                    PendingSocialState updated = pending.withPending(targetUsername);
                                                    byte[] raw = updated.toCbor().serialize();
                                                    return getUserRoot().thenCompose(home -> home.uploadFileSection(
                                                            SOCIAL_STATE_FILENAME, AsyncReader.build(raw), true, 0, raw.length, Optional.empty(),
                                                            true, network, crypto, x -> {}, crypto.random.randomBytes(32)))
                                                            .thenApply(x -> b);
                                                }));
                            });
                });
            });
        });
    }

    @JsMethod
    public CompletableFuture<SocialFeed> getSocialFeed() {
        return getByPath(Paths.get(username, FEED_DIR_NAME))
                .thenCompose(feedDirOpt -> {
                    if (feedDirOpt.isEmpty())
                        return SocialFeed.create(this);
                    return SocialFeed.load(feedDirOpt.get(), this);
                });
    }

    public CompletableFuture<Boolean> unShareReadAccess(Path path, String readerToRemove) {
        return unShareReadAccessWith(path, Collections.singleton(readerToRemove));
    }

    public CompletableFuture<Boolean> unShareWriteAccess(Path path, String writerToRemove) {
        return unShareWriteAccessWith(path, Collections.singleton(writerToRemove));
    }

    private CompletableFuture<Snapshot> rotateAllKeys(FileWrapper file,
                                                      FileWrapper parent,
                                                      boolean rotateSigners) {
        // 1) rotate all the symmetric keys and optionally signers
        // 2) if parent signer is different, add a link node pointing to the new child
        // 2) update parent pointer to new child/link
        // 3) delete old subtree
        PublicKeyHash owner = parent.owner();
        SigningPrivateKeyAndPublicHash parentSigner = parent.signingPair();
        AbsoluteCapability parentCap = parent.getPointer().capability;
        AbsoluteCapability originalCap = file.getPointer().capability;
        return network.synchronizer.applyComplexUpdate(owner, parentSigner, (initial, c) -> (rotateSigners ?
                CryptreeNode.initAndAuthoriseSigner(
                        owner,
                        parentSigner,
                        SigningKeyPair.random(crypto.random, crypto.signer), network, initial, c) :
                Futures.of(new Pair<>(initial, file.signingPair())))
                .thenCompose(p -> {
                    Optional<RelativeCapability> newParentLink = Optional.of(
                            rotateSigners ?
                                    new RelativeCapability(
                                            Optional.of(parent.writer()),
                                            crypto.random.randomBytes(RelativeCapability.MAP_KEY_LENGTH),
                                            SymmetricKey.random(),
                                            Optional.empty()):
                                    new RelativeCapability(
                                            Optional.empty(),
                                            parent.getPointer().capability.getMapKey(),
                                            parent.getParentKey(),
                                            Optional.empty())
                    );
                    return file.getPointer().fileAccess.rotateAllKeys(
                            true,
                            new CryptreeNode.CapAndSigner((WritableAbsoluteCapability)
                                    originalCap, file.signingPair()),
                            new CryptreeNode.CapAndSigner(new WritableAbsoluteCapability(
                                    owner,
                                    p.right.publicKeyHash,
                                    crypto.random.randomBytes(RelativeCapability.MAP_KEY_LENGTH),
                                    SymmetricKey.random(),
                                    SymmetricKey.random()),
                                    p.right),
                            new CryptreeNode.CapAndSigner((WritableAbsoluteCapability) parentCap, parent.signingPair()),
                            new CryptreeNode.CapAndSigner((WritableAbsoluteCapability) parentCap, parent.signingPair()),
                            newParentLink,
                            Optional.empty(),
                            rotateSigners,
                            network,
                            crypto,
                            p.left,
                            c)
                            .thenCompose(rotated -> {
                                // add a link in same writing space as parent to restrict rename access
                                if (rotateSigners) {
                                    SymmetricKey linkRBase = SymmetricKey.random();
                                    SymmetricKey linkParent = newParentLink.get().rBaseKey;
                                    SymmetricKey linkWBase = SymmetricKey.random();
                                    byte[] linkMapKey = newParentLink.get().getMapKey();
                                    WritableAbsoluteCapability linkCap = new WritableAbsoluteCapability(owner,
                                            parentCap.writer, linkMapKey, linkRBase, linkWBase);
                                    return CryptreeNode.createAndCommitLink(parent, rotated.right,
                                            file.getFileProperties(), linkCap, linkParent,
                                            crypto, network, rotated.left, c)
                                            .thenApply(newSnapshot -> new Pair<>(newSnapshot, linkCap));
                                } else
                                    return Futures.of(rotated);
                            });
                }).thenCompose(rotated ->
                                parent.getPointer().fileAccess.updateChildLink(
                                        rotated.left, c, (WritableAbsoluteCapability) parentCap,
                                        parentSigner, file.isLink() ? file.getLinkPointer().capability : originalCap,
                                        new NamedAbsoluteCapability(file.getName(), rotated.right),
                                        network, crypto.hasher)
                                        .thenCompose(s -> IpfsTransaction.call(owner,
                                                tid -> FileWrapper.deleteAllChunks(
                                                        file.writableFilePointer(),
                                                        file.signingPair(),
                                                        tid, crypto.hasher, network, s, c), network.dhtClient))
                                        .thenCompose(s -> rotateSigners ?
                                                CryptreeNode.deAuthoriseSigner(owner, parentSigner, file.writer(),
                                                        network, s, c) :
                                                Futures.of(s)))
        );
    }

    /**
     * Remove read access to a file for the supplied readers.
     * The readers can include the inbuilt friend groupUid and followers groupUid
     * If the friend group is supplied - in addition to removing read access for the friend group,
     * all individual friends that currently have read access will lose read access
     * If the followers group is supplied - in addition to removing read access for the follower group AND friend
     * group all individual users that currently have read access will lose read access
     *
     * @param path - The path to the file/dir to revoke access to
     * @param initialReadersToRemove - The usernames or groupUids to revoke read access to
     * @return
     */
    @JsMethod
    public CompletableFuture<Boolean> unShareReadAccessWith(Path path, Set<String> initialReadersToRemove) {
        //does list of readers include groups?
        boolean hasGroups = initialReadersToRemove.stream().anyMatch(i -> i.startsWith("."));
        return (hasGroups ?
                getSocialState().thenCompose(social -> sharedWith(path)
                        .thenApply(fileSharingState ->
                            gatherAllUsernamesToUnshare(social, fileSharingState.readAccess, initialReadersToRemove)
                        )) :
                Futures.of(initialReadersToRemove))
                .thenCompose(readersToRemove -> {
                    String pathString = path.toString();
                    String absolutePathString = pathString.startsWith("/") ? pathString : "/" + pathString;
                    return getByPath(absolutePathString).thenCompose(opt -> {
                        FileWrapper toUnshare = opt.orElseThrow(() -> new IllegalStateException("Specified un-shareWith path " + absolutePathString + " does not exist"));
                        // now change to new base keys, clean some keys and mark others as dirty
                        return getByPath(path.getParent().toString())
                                .thenCompose(parent -> rotateAllKeys(toUnshare, parent.get(), false)
                                        .thenCompose(markedDirty -> {
                                            return sharedWithCache.removeSharedWith(SharedWithCache.Access.READ, path, readersToRemove)
                                                    .thenCompose(b -> reSendAllWriteAccessRecursive(path))
                                                    .thenCompose(b -> reSendAllReadAccessRecursive(path));
                                        }));
                    });
                });
    }

    /**
     * Remove write access to a file for the supplied writers.
     * The readers can include the inbuilt friend groupUid and followers groupUid
     * If the friend group is supplied - in addition to removing write access for the friend group,
     * all individual friends that currently have write access will lose write access
     * If the followers group is supplied - in addition to removing write access for the follower group AND friend
     * group all individual users that currently have write access will lose write access
     *
     * @param path - The path to the file/dir to revoke access to
     * @param initialWritersToRemove - The usernames or groupUids to revoke write access to
     * @return
     */
    @JsMethod
    public CompletableFuture<Boolean> unShareWriteAccessWith(Path path, Set<String> initialWritersToRemove) {
        //does list of readers include groups?
        boolean hasGroups = initialWritersToRemove.stream().anyMatch(i -> i.startsWith("."));
        return (hasGroups ?
                getSocialState().thenCompose(social -> sharedWith(path)
                        .thenApply(fileSharingState ->
                            gatherAllUsernamesToUnshare(social, fileSharingState.writeAccess, initialWritersToRemove)
                        )) :
                Futures.of(initialWritersToRemove))
                .thenCompose(writersToRemove -> {
                    // 1. Authorise new writer pair as an owned key to parent's writer
                    // 2. Rotate all keys (except data keys which are marked as dirty)
                    // 3. Update link from parent to point to new rotated child
                    // 4. Delete old file and subtree
                    // 5. Remove old writer from parent owned keys
                    String pathString = path.toString();
                    String absolutePathString = pathString.startsWith("/") ? pathString : "/" + pathString;
                    return getByPath(absolutePathString).thenCompose(opt -> {
                        FileWrapper toUnshare = opt.orElseThrow(() -> new IllegalStateException("Specified un-shareWith path " + absolutePathString + " does not exist"));
                        return getByPath(path.getParent().toString())
                                .thenCompose(parentOpt -> {
                                    FileWrapper parent = parentOpt.get();
                                    return rotateAllKeys(toUnshare, parent, true)
                                            .thenCompose(x ->
                                                    sharedWithCache.removeSharedWith(SharedWithCache.Access.WRITE,
                                                            path, writersToRemove))
                                            .thenCompose(b -> reSendAllWriteAccessRecursive(path))
                                            .thenCompose(b -> reSendAllReadAccessRecursive(path));
                                });
                    });
                });
    }

    @JsMethod
    public CompletableFuture<FileSharedWithState> sharedWith(Path p) {
        return sharedWithCache.getSharedWith(p);
    }

    @JsMethod
    public CompletableFuture<SharedWithState> getDirectorySharingState(Path dir) {
        // The global root and home folders cannot be shared
        if (dir.getNameCount() == 0 || username == null)
            return Futures.of(SharedWithState.empty());
        return sharedWithCache.getDirSharingState(dir);
    }

    @JsMethod
    public CompletableFuture<Boolean> shareReadAccessWithFriends(Path path) {
        return getSocialState()
                .thenApply(s -> s.getFriendsGroupUid())
                .thenCompose(friendsGroupUid -> getByPath(path.toString())
                        .thenCompose(file -> shareReadAccessWith(file.orElseThrow(() ->
                                new IllegalStateException("Could not find path " + path.toString())), path, Collections.singleton(friendsGroupUid))));
    }

    @JsMethod
    public CompletableFuture<Boolean> shareReadAccessWithFollowers(Path path) {
        return getSocialState()
                .thenApply(s -> s.getFollowersGroupUid())
                .thenCompose(followersGroupUid -> getByPath(path.toString())
                        .thenCompose(file -> shareReadAccessWith(file.orElseThrow(() ->
                                new IllegalStateException("Could not find path " + path.toString())), path, Collections.singleton(followersGroupUid))));
    }

    /*
        Taking into account currently shared users/groups and users/groups selected for unsharing, build a list that is group aware
        Note: Only inbuilt groups of friends and followers are currently handled
     */
    private Set<String> gatherAllUsernamesToUnshare(SocialState social,
                                                    Set<String> currentSharedWithUsernames,
                                                    Set<String> usernamesToUnshare) {

        Set<String> followers = social.getFollowers();
        Set<String> friends = social.getFriends();

        String friendGroupUid = social.getFriendsGroupUid();
        String followersGroupUid = social.getFollowersGroupUid();

        Set<String> usersToUnshare = new HashSet<>(usernamesToUnshare);
        if (usernamesToUnshare.contains(friendGroupUid)) {
            HashSet<String> toAdd = new HashSet<>(currentSharedWithUsernames);
            toAdd.retainAll(friends);
            usersToUnshare.addAll(toAdd);
        }
        if (usernamesToUnshare.contains(followersGroupUid)) {
            HashSet<String> toAdd = new HashSet<>(currentSharedWithUsernames);
            toAdd.retainAll(followers);
            usersToUnshare.addAll(toAdd);
            if (currentSharedWithUsernames.contains(friendGroupUid)) {
                usersToUnshare.add(friendGroupUid);
            }
        }
        return usersToUnshare;
    }

    @JsMethod
    public CompletableFuture<Boolean> shareReadAccessWith(Path path, Set<String> readersToAdd) {
        if (readersToAdd.isEmpty())
            return Futures.of(true);

        return getByPath(path.toString())
                .thenCompose(file -> shareReadAccessWith(file.orElseThrow(() ->
                        new IllegalStateException("Could not find path " + path.toString())), path, readersToAdd));
    }

    public CompletableFuture<Boolean> reSendAllWriteAccessRecursive(Path start) {
        return sharedWithCache.getAllWriteShares(start)
                .thenCompose(toReshare -> Futures.reduceAll(toReshare.entrySet(),
                        true,
                        (b, e) -> sendWriteCapToAll(e.getKey(), e.getValue()),
                        (a, b) -> a));
    }

    public CompletableFuture<Boolean> reSendAllReadAccessRecursive(Path start) {
        return sharedWithCache.getAllReadShares(start)
                .thenCompose(toReshare -> Futures.reduceAll(toReshare.entrySet(),
                        true,
                        (b, e) -> shareReadAccessWith(e.getKey(), e.getValue()),
                        (a, b) -> a));
    }

    private CompletableFuture<Boolean> shareReadAccessWith(FileWrapper file, Path p, Set<String> readersToAdd) {
        ensureAllowedToShare(file, username, false);
        BiFunction<FileWrapper, FileWrapper, CompletableFuture<Boolean>> sharingFunction = (sharedDir, fileWrapper) ->
                CapabilityStore.addReadOnlySharingLinkTo(sharedDir, fileWrapper.getPointer().capability,
                        network, crypto)
                        .thenCompose(ee -> CompletableFuture.completedFuture(true));
        return Futures.reduceAll(readersToAdd,
                true,
                (x, username) -> shareAccessWith(file, username, sharingFunction),
                (a, b) -> a && b).thenCompose(result -> {
            if (!result) {
                CompletableFuture<Boolean> res = new CompletableFuture<>();
                res.complete(false);
                return res;
            }
            return updatedSharedWithCache(file, p, readersToAdd, SharedWithCache.Access.READ);
        });
    }

    @JsMethod
    public CompletableFuture<Boolean> shareWriteAccessWith(Path fileToShare,
                                                               Set<String> writersToAdd) {
        return getByPath(fileToShare.getParent())
                .thenCompose(parentOpt -> ! parentOpt.isPresent() ?
                                Futures.errored(new IllegalStateException("Unable to read " + fileToShare.getParent())) :
                parentOpt.get().getChild(fileToShare.getFileName().toString(), crypto.hasher, network)
                        .thenCompose(fileOpt -> ! fileOpt.isPresent() ?
                                Futures.errored(new IllegalStateException("Unable to read " + fileToShare)) :
                                shareWriteAccessWith(fileOpt.get(), fileToShare, parentOpt.get(), writersToAdd)));
    }

    private CompletableFuture<Boolean> shareWriteAccessWith(FileWrapper file,
                                                              Path pathToFile,
                                                              FileWrapper parent,
                                                              Set<String> writersToAdd) {
        // There are 2 situations:
        // a) file already has a different signing key than parent,
        //    in which case, just share a write cap
        //
        // b) file needs to be moved to a different signing key (along with its subtree)
        // To do this atomically,
        // 1) rotate all the keys as if we were revoking write access
        // 2) update parent pointer
        // 3) delete old subtree
        // 4) then reshare all sub sharees
        ensureAllowedToShare(file, username, true);
        SigningPrivateKeyAndPublicHash currentSigner = file.signingPair();
        boolean changeSigner = currentSigner.publicKeyHash.equals(parent.signingPair().publicKeyHash);

        if (! changeSigner) {
            return sharedWithCache.addSharedWith(SharedWithCache.Access.WRITE, pathToFile, writersToAdd)
                    .thenCompose(b -> sendWriteCapToAll(pathToFile, writersToAdd));
        }

        return rotateAllKeys(file, parent, true)
                .thenCompose(s -> getByPath(pathToFile)
                        .thenCompose(newFileOpt -> sharedWithCache
                                .addSharedWith(SharedWithCache.Access.WRITE, pathToFile, writersToAdd))
                        .thenCompose(b -> reSendAllWriteAccessRecursive(pathToFile))
                        .thenCompose(b -> reSendAllReadAccessRecursive(pathToFile))
                );
    }

    public CompletableFuture<Boolean> sendWriteCapToAll(Path toFile, Set<String> writersToAdd) {
        if (writersToAdd.isEmpty())
            return Futures.of(true);

        System.out.println("Resharing WRITE cap to " + toFile + " with " + writersToAdd);
        return getByPath(toFile.getParent())
                .thenCompose(parent -> getByPath(toFile)
                        .thenCompose(fileOpt -> fileOpt.map(file -> sendWriteCapToAll(file, parent.get(), toFile, writersToAdd))
                                .orElseGet(() -> Futures.errored(
                                        new IllegalStateException("Couldn't retrieve file at " + toFile)))));
    }

    public CompletableFuture<Boolean> sendWriteCapToAll(FileWrapper file,
                                                        FileWrapper parent,
                                                        Path pathToFile,
                                                        Set<String> writersToAdd) {
        if (parent.writer().equals(file.writer()))
            return Futures.errored(
                    new IllegalStateException("A file must have different writer than its parent to grant write access!"));
        BiFunction<FileWrapper, FileWrapper, CompletableFuture<Boolean>> sharingFunction =
                (sharedDir, fileToShare) -> CapabilityStore.addEditSharingLinkTo(sharedDir,
                        file.writableFilePointer(), network, crypto)
                        .thenCompose(ee -> CompletableFuture.completedFuture(true));
        return Futures.reduceAll(writersToAdd,
                true,
                (x, username) -> shareAccessWith(file, username, sharingFunction),
                (a, b) -> a && b).thenCompose(result -> {
            if (!result) {
                return Futures.of(false);
            }
            return updatedSharedWithCache(file, pathToFile, writersToAdd, SharedWithCache.Access.WRITE);
        });
    }

    private CompletableFuture<Boolean> updatedSharedWithCache(FileWrapper file,
                                                              Path pathToFile,
                                                              Set<String> usersToAdd,
                                                              SharedWithCache.Access access) {
        return sharedWithCache.addSharedWith(access, pathToFile, usersToAdd);
    }

    public CompletableFuture<Boolean> shareAccessWith(FileWrapper file, String usernameToGrantAccess,
                                                      BiFunction<FileWrapper, FileWrapper, CompletableFuture<Boolean>> sharingFunction) {
        return getByPath("/" + username + "/shared/" + usernameToGrantAccess)
                .thenCompose(shared -> {
                    if (!shared.isPresent())
                        return Futures.errored(new IllegalStateException("Unknown recipient for sharing: " + usernameToGrantAccess));
                    FileWrapper sharedDir = shared.get();
                    return sharingFunction.apply(sharedDir, file);
                });
    }

    private static CompletableFuture<Snapshot> addRootEntryPointAndCommit(Snapshot version,
                                                                          EntryPoint entry,
                                                                          SigningPrivateKeyAndPublicHash owner,
                                                                          SymmetricKey rootKey,
                                                                          NetworkAccess network,
                                                                          TransactionId tid) {
        CommittedWriterData cwd = version.get(owner.publicKeyHash);
        WriterData wd = cwd.props;
        Optional<UserStaticData> updated = wd.staticData.map(sd -> {
            UserStaticData.EntryPoints data = sd.getData(rootKey);
            List<EntryPoint> entryPoints = data.entries;
            entryPoints.add(entry);
            return new UserStaticData(entryPoints, rootKey, data.boxer);
        });
        return wd.withStaticData(updated).commit(owner.publicKeyHash, owner, cwd.hash, network, tid);
    }

    private synchronized CompletableFuture<FileWrapper> addExternalEntryPoint(EntryPoint entry) {
        boolean isOurs = username.equals(entry.ownerName);
        if (isOurs)
            throw new IllegalStateException("Cannot add an entry point to your won filesystem!");
        String filename = ENTRY_POINTS_FROM_FRIENDS_FILENAME;
        // verify owner before adding
        return entry.isValid("/" + entry.ownerName, network)
                .thenCompose(valid -> valid ?
                        getByPath(Paths.get(username, filename)) :
                        Futures.errored(new IllegalStateException("Incorrect claimed owner for entry point")))
                .thenCompose(existing -> {
                    long offset = existing.map(f -> f.getSize()).orElse(0L);
                    byte[] data = entry.serialize();
                    AsyncReader reader = AsyncReader.build(data);
                    Optional<SymmetricKey> base = existing.map(f -> f.getPointer().capability.rBaseKey);
                    return getUserRoot().thenCompose(home ->
                            home.uploadFileSection(filename, reader, true, offset,
                                    offset + data.length, base, true, network, crypto, x -> {},
                                    crypto.random.randomBytes(32)));
                });
    }

    public CompletableFuture<List<BlindFollowRequest>> getFollowRequests() {
        byte[] auth = TimeLimitedClient.signNow(signer.secret);
        return network.social.getFollowRequests(signer.publicKeyHash, auth).thenApply(reqs -> {
            CborObject cbor = CborObject.fromByteArray(reqs);
            if (!(cbor instanceof CborObject.CborList))
                throw new IllegalStateException("Invalid cbor for list of follow requests: " + cbor);
            return ((CborObject.CborList) cbor).value.stream()
                    .map(BlindFollowRequest::fromCbor)
                    .collect(Collectors.toList());
        });
    }

    /**
     * Process any responses to our follow requests.
     *
     * @return initial follow requests
     */
    public CompletableFuture<List<FollowRequestWithCipherText>> processFollowRequests() {
        return getFollowRequests().thenCompose(this::processFollowRequests);
    }

    private CompletableFuture<List<FollowRequestWithCipherText>> processFollowRequests(List<BlindFollowRequest> all) {
        return getSharingFolder().thenCompose(sharing ->
                getFollowerRoots(false).thenCompose(followerRoots -> getPendingOutgoingFollowRequests()
                        .thenCompose(pendingOut -> {
                    List<FollowRequestWithCipherText> withDecrypted = all.stream()
                            .map(b -> new FollowRequestWithCipherText(b.followRequest.decrypt(boxer.secretBoxingKey, b.dummySource, FollowRequest::fromCbor), b))
                            .collect(Collectors.toList());

                    List<FollowRequestWithCipherText> replies = withDecrypted.stream()
                            .filter(p -> pendingOut.pendingOutgoingFollowRequests.contains(p.req.entry.get().ownerName))
                            .collect(Collectors.toList());

                    BiFunction<TrieNode, FollowRequestWithCipherText, CompletableFuture<TrieNode>> addToStatic = (root, p) -> {
                        FollowRequest freq = p.req;
                        if (! Arrays.equals(freq.entry.get().pointer.rBaseKey.serialize(), SymmetricKey.createNull().serialize())) {
                            CompletableFuture<TrieNode> updatedRoot = freq.entry.get().ownerName.equals(username) ?
                                    CompletableFuture.completedFuture(root) : // ignore responses claiming to be owned by us
                                    addExternalEntryPoint(freq.entry.get())
                                    .thenCompose(x -> removeFromPendingOutgoing(freq.entry.get().ownerName))
                                    .thenCompose(x -> retrieveAndAddEntryPointToTrie(root, freq.entry.get()));
                            return updatedRoot.thenCompose(newRoot -> {
                                entrie = newRoot;
                                // clear their response follow req too
                                return network.social.removeFollowRequest(signer.publicKeyHash, signer.secret.signMessage(p.cipher.serialize()))
                                        .thenApply(b -> newRoot);
                            });
                        }
                        return network.social.removeFollowRequest(signer.publicKeyHash, signer.secret.signMessage(p.cipher.serialize()))
                                .thenApply(b -> root);
                    };

                    BiFunction<TrieNode, FollowRequestWithCipherText, CompletableFuture<TrieNode>> mozart = (trie, p) -> {
                        FollowRequest freq = p.req;
                        // delete our folder if they didn't reciprocate
                        String theirName = freq.entry.get().ownerName;
                        FileWrapper ourDirForThem = followerRoots.get(theirName);
                        byte[] ourKeyForThem = ourDirForThem.getKey().serialize();
                        Optional<byte[]> keyFromResponse = freq.key.map(Cborable::serialize);
                        if (keyFromResponse.isEmpty()) {
                            // They didn't reciprocate (follow us)
                            CompletableFuture<FileWrapper> removeDir = ourDirForThem.remove(sharing,
                                    Paths.get(username, SHARED_DIR_NAME, theirName), this);

                            return removeDir.thenCompose(x -> removeFromPendingOutgoing(freq.entry.get().ownerName))
                                    .thenCompose(b -> addToStatic.apply(trie, p));
                        } else if (freq.entry.get().pointer.isNull()) {
                            // They reciprocated, but didn't accept (they follow us, but we can't follow them)
                            // add entry point to static data to signify their acceptance
                            // and finally remove the follow request
                            EntryPoint entryWeSentToThem = new EntryPoint(ourDirForThem.getPointer().capability.readOnly(),
                                    username);
                            // add them to followers group
                            return getGroupUid(SocialState.FOLLOWERS_GROUP_NAME)
                                    .thenCompose(followersUidOpt -> shareReadAccessWith(Paths.get(username,
                                            SHARED_DIR_NAME, followersUidOpt.get()), Collections.singleton(theirName)))
                                    .thenCompose(x -> network.social.removeFollowRequest(signer.publicKeyHash, signer.secret.signMessage(p.cipher.serialize())))
                                    .thenApply(x -> trie);
                        } else {
                            // they accepted and reciprocated
                            // add entry point to static data to signify their acceptance
                            EntryPoint entryWeSentToThem = new EntryPoint(ourDirForThem.getPointer().capability.readOnly(),
                                    username);

                            // add new entry point to tree root
                            EntryPoint entry = freq.entry.get();
                            if (entry.ownerName.equals(username))
                                throw new IllegalStateException("Received a follow request claiming to be owned by us!");
                            // add them to followers and friends group
                            return getGroupUid(SocialState.FOLLOWERS_GROUP_NAME)
                                    .thenCompose(followersUidOpt -> shareReadAccessWith(Paths.get(username,
                                            SHARED_DIR_NAME, followersUidOpt.get()), Collections.singleton(theirName)))
                                    .thenCompose(x -> getGroupUid(SocialState.FRIENDS_GROUP_NAME)
                                            .thenCompose(friendsUidOpt -> shareReadAccessWith(Paths.get(username,
                                                    SHARED_DIR_NAME, friendsUidOpt.get()), Collections.singleton(theirName))))
                                    .thenCompose(x -> NetworkAccess.getLatestEntryPoint(entry, network)
                                            .thenCompose(r -> addToStatic.apply(trie.put(r.getPath(), r.entry), p.withEntryPoint(r.entry))))
                                    .exceptionally(t -> trie);
                        }
                    };
                    List<FollowRequestWithCipherText> initialRequests = withDecrypted.stream()
                            .filter(p -> !followerRoots.containsKey(p.req.entry.get().ownerName))
                            .collect(Collectors.toList());
                    return Futures.reduceAll(replies, entrie, mozart, (a, b) -> a)
                            .thenApply(newRoot -> {
                                entrie = newRoot;
                                return initialRequests;
                            });
                }))
        );
    }

    @JsMethod
    public CompletableFuture<List<Pair<SharedItem, FileWrapper>>> getFiles(List<SharedItem> pointers) {
        return Futures.combineAllInOrder(pointers.stream()
                .map(s -> Futures.asyncExceptionally(() -> network.getFile(s.cap, s.owner)
                                .thenCompose(fopt -> fopt.map(f -> Futures.of(Optional.of(f)))
                                        .orElseGet(() -> getByPath(s.path))),
                        t -> getByPath(s.path))
                        .thenApply(opt -> opt.map(f -> new Pair<>(s, f))))
                .collect(Collectors.toList()))
                .thenApply(res -> res.stream()
                        .flatMap(Optional::stream)
                        .collect(Collectors.toList()));
    }

    public CompletableFuture<Set<FileWrapper>> getChildren(String path) {
        FileProperties.ensureValidPath(path);
        return entrie.getChildren(path, crypto.hasher, network);
    }

    public CompletableFuture<Optional<FileWrapper>> getByPath(Path path) {
        return getByPath(path.toString());
    }

    @JsMethod
    public CompletableFuture<Optional<FileWrapper>> getByPath(String path) {
        if (path.equals("/"))
            return CompletableFuture.completedFuture(Optional.of(FileWrapper.createRoot(entrie)));
        FileProperties.ensureValidPath(path);
        String absolutePath = path.startsWith("/") ? path : "/" + path;
        return entrie.getByPath(absolutePath, crypto.hasher, network);
    }

    public CompletableFuture<FileWrapper> getUserRoot() {
        return getByPath("/" + username).thenApply(opt -> opt.get());
    }

    /**
     * @return TrieNode for root of filesystem containing only our files
     */
    private static CompletableFuture<TrieNode> createOurFileTreeOnly(String ourName,
                                                                     SymmetricKey rootKey,
                                                                     WriterData userData,
                                                                     NetworkAccess network,
                                                                     Crypto crypto) {
        TrieNode root = TrieNodeImpl.empty();
        if (!userData.staticData.isPresent())
            throw new IllegalStateException("Cannot retrieve file tree for a filesystem without entrypoints!");
        List<EntryPoint> ourFileSystemEntries = userData.staticData.get()
                .getData(rootKey).entries
                .stream()
                .filter(e -> e.ownerName.equals(ourName))
                .map(e -> e.withOwner(userData.controller))
                .collect(Collectors.toList());
        return Futures.reduceAll(ourFileSystemEntries, root,
                (t, e) -> NetworkAccess.getLatestEntryPoint(e, network)
                        .thenApply(r -> t.put(r.getPath(), r.entry)),
                (a, b) -> a)
                .exceptionally(Futures::logAndThrow);
    }

    /**
     * @return TrieNode for root of filesystem
     */
    private CompletableFuture<TrieNode> createFileTree(TrieNode ourRoot,
                                                       String ourName,
                                                       NetworkAccess network,
                                                       Crypto crypto) {
        // need to to retrieve all the entry points of our friends and any of their groups
        return ourRoot.getByPath(ourName, crypto.hasher, network)
                        .thenApply(Optional::get)
                .thenCompose(homeDir -> time(() -> getFriendsEntryPoints(homeDir), "Get friend's entry points")
                        .thenCompose(friendEntries -> homeDir.getChild(CapabilityStore.CAPABILITY_CACHE_DIR, crypto.hasher, network)
                                .thenCompose(copt -> {
                                    List<EntryPoint> friendsOnly = friendEntries.stream()
                                            .filter(e -> !e.ownerName.equals(ourName))
                                            .collect(Collectors.toList());

                                    List<CompletableFuture<Optional<FriendSourcedTrieNode>>> friendNodes = friendsOnly.stream()
                                            .parallel()
                                            .map(e -> FriendSourcedTrieNode.build(capCache, e,
                                                    (c, o) -> addFriendGroupCap(c, o), network, crypto))
                                            .collect(Collectors.toList());
                                    return Futures.reduceAll(friendNodes, ourRoot,
                                            (t, e) -> e.thenApply(fromUser -> fromUser.map(userEntrie -> t.putNode(userEntrie.ownerName, userEntrie))
                                                    .orElse(t)).exceptionally(ex -> t),
                                            (a, b) -> a);
                                })).thenCompose(root -> getFriendsGroupCaps(homeDir)
                                .thenApply(groups -> { // now add the groups from each friend
                                    Set<String> friendNames = root.getChildNames()
                                            .stream()
                                            .filter(n -> !n.equals(ourName))
                                            .collect(Collectors.toSet());
                                    for (String friendName : friendNames) {
                                        FriendSourcedTrieNode friend = (FriendSourcedTrieNode) root.getChildNode(friendName);
                                        for (EntryPoint group : groups.left.getFriends(friendName)) {
                                            friend.addGroup(group);
                                        }
                                    }
                                    return root;
                                })))
                .exceptionally(Futures::logAndThrow);
    }

    private CompletableFuture<TrieNode> retrieveAndAddEntryPointToTrie(TrieNode root, EntryPoint e) {
        return NetworkAccess.retrieveEntryPoint(e, network)
                .thenCompose(r -> addRetrievedEntryPointToTrie(username, root, r.entry, r.getPath(), false,
                        capCache, this, network, crypto));
    }

    private CompletableFuture<List<EntryPoint>> getFriendsEntryPoints(FileWrapper homeDir) {
        return homeDir.getChild(ENTRY_POINTS_FROM_FRIENDS_FILENAME, crypto.hasher, network)
                .thenCompose(fopt -> {
                    return fopt.map(f -> {
                        List<EntryPoint> res = new ArrayList<>();
                        return f.getInputStream(network, crypto, x -> {})
                                .thenCompose(reader -> reader.parseStream(EntryPoint::fromCbor, res::add, f.getSize())
                                        .thenApply(x -> res));
                    }).orElse(CompletableFuture.completedFuture(Collections.emptyList()))
                            .thenCompose(fromFriends -> {
                                // filter out blocked friends
                                return homeDir.getChild(BLOCKED_USERNAMES_FILE, crypto.hasher, network)
                                        .thenCompose(bopt -> bopt.map(f -> f.getInputStream(network, crypto, x -> {})
                                                .thenCompose(in -> Serialize.readFully(in, f.getSize()))
                                                .thenApply(data -> new HashSet<>(Arrays.asList(new String(data).split("\n")))
                                                        .stream()
                                                        .collect(Collectors.toSet())))
                                                .orElse(CompletableFuture.completedFuture(Collections.emptySet()))
                                                .thenApply(toRemove -> fromFriends.stream()
                                                        .filter(e -> !toRemove.contains(e.ownerName))
                                                        .collect(Collectors.toList())));
                            });
                }).thenApply(entries -> {
                    // Only take the most recent version of each entry
                    Map<PublicKeyHash, EntryPoint> latest = new LinkedHashMap<>();
                    entries.forEach(e -> latest.put(e.pointer.writer, e));
                    return latest.values()
                            .stream()
                            .collect(Collectors.toList());
                });
    }

    private CompletableFuture<Pair<FriendsGroups, Optional<FileWrapper>>> getFriendsGroupCaps(FileWrapper homeDir) {
        return homeDir.getChild(ENTRY_POINTS_FROM_FRIENDS_GROUPS_FILENAME, crypto.hasher, network)
                .thenCompose(fopt -> fopt.map(f -> f.getInputStream(network, crypto, x -> {})
                        .thenCompose(reader -> Serialize.parse(reader, f.getSize(), FriendsGroups::fromCbor))
                        .thenApply(g -> new Pair<>(g, fopt)))
                        .orElse(CompletableFuture.completedFuture(new Pair<>(FriendsGroups.empty(), Optional.empty()))));
    }

    public CompletableFuture<Boolean> addFriendGroupCap(CapabilityWithPath group, String owner) {
        return getUserRoot()
                .thenCompose(home -> getFriendsGroupCaps(home)
                        .thenCompose(p -> {
                            FriendsGroups updated = p.left.addGroup(group, owner);
                            byte[] raw = updated.serialize();
                            AsyncReader reader = AsyncReader.build(raw);
                            if (p.right.isPresent())
                                return p.right.get().overwriteFile(reader, raw.length, network, crypto, x -> {});

                            return home.uploadFileSection(ENTRY_POINTS_FROM_FRIENDS_GROUPS_FILENAME, reader, true,
                                    0, raw.length, Optional.empty(), false, network, crypto, x -> {},
                                    crypto.random.randomBytes(RelativeCapability.MAP_KEY_LENGTH));
                        })).thenApply(x -> true);
    }

    private static CompletableFuture<TrieNode> addRetrievedEntryPointToTrie(String ourName,
                                                                            TrieNode root,
                                                                            EntryPoint fileCap,
                                                                            String path,
                                                                            boolean checkOwner,
                                                                            IncomingCapCache capCache,
                                                                            UserContext context,
                                                                            NetworkAccess network,
                                                                            Crypto crypto) {
        // check entrypoint doesn't forge the owner
        return (fileCap.ownerName.equals(ourName) || ! checkOwner ? CompletableFuture.completedFuture(true) :
                fileCap.isValid(path, network)).thenCompose(valid -> {
            if (! valid)
                return Futures.errored(new IllegalStateException("Capability claims incorrect owner!"));
            String[] parts = path.split("/");
            if (parts.length < 3 || !parts[2].equals(SHARED_DIR_NAME))
                return CompletableFuture.completedFuture(root.put(path, fileCap));
            String username = parts[1];
            if (username.equals(ourName)) // This is a sharing directory of ours for a friend
                return CompletableFuture.completedFuture(root);
            // This is a friend's sharing directory, create a wrapper to read the capabilities lazily from it
            return root.getByPath(Paths.get(ourName, CapabilityStore.CAPABILITY_CACHE_DIR).toString(), crypto.hasher, network)
                    .thenApply(opt -> opt.get())
                    .thenCompose(cacheDir -> FriendSourcedTrieNode.build(capCache, fileCap, context::addFriendGroupCap, network, crypto))
                    .thenApply(fromUser -> fromUser.map(userEntrie -> root.putNode(username, userEntrie)).orElse(root));
        });
    }

    public static CompletableFuture<CommittedWriterData> getWriterData(NetworkAccess network,
                                                                       PublicKeyHash owner,
                                                                       PublicKeyHash writer) {
        return getWriterDataCbor(network.dhtClient, network.mutable, owner, writer)
                .thenApply(pair -> new CommittedWriterData(MaybeMultihash.of(pair.left), WriterData.fromCbor(pair.right)));
    }

    public static CompletableFuture<CommittedWriterData> getWriterData(ContentAddressedStorage ipfs,
                                                                       MutablePointers mutable,
                                                                       PublicKeyHash owner,
                                                                       PublicKeyHash writer) {
        return getWriterDataCbor(ipfs, mutable, owner, writer)
                .thenApply(pair -> new CommittedWriterData(MaybeMultihash.of(pair.left), WriterData.fromCbor(pair.right)));
    }

    public static CompletableFuture<Pair<Multihash, CborObject>> getWriterDataCbor(NetworkAccess network, String username) {
        return network.coreNode.getPublicKeyHash(username)
                .thenCompose(signer -> {
                    PublicKeyHash owner = signer.orElseThrow(
                            () -> new IllegalStateException("No public-key for user " + username));
                    return getWriterDataCbor(network.dhtClient, network.mutable, owner, owner);
                });
    }

    private static CompletableFuture<Pair<Multihash, CborObject>> getWriterDataCbor(ContentAddressedStorage ipfs,
                                                                                    MutablePointers mutable,
                                                                                    PublicKeyHash owner,
                                                                                    PublicKeyHash writer) {
        return mutable.getPointer(owner, writer)
                .thenCompose(casOpt -> ipfs.getSigningKey(writer)
                        .thenApply(signer -> casOpt.map(raw -> HashCasPair.fromCbor(CborObject.fromByteArray(
                                signer.get().unsignMessage(raw))).updated)
                                .orElse(MaybeMultihash.empty())))
                .thenCompose(key -> ipfs.get(key.get())
                        .thenApply(Optional::get)
                        .thenApply(cbor -> new Pair<>(key.get(), cbor))
                );
    }

    @JsMethod
    public CompletableFuture<Boolean> unfollow(String friendName) {
        LOG.info("Unfollowing: " + friendName);
        return getUserRoot()
                .thenCompose(home -> home.getChild(BLOCKED_USERNAMES_FILE, crypto.hasher, network)
                        .thenCompose(fopt -> home.appendToChild(BLOCKED_USERNAMES_FILE,
                                fopt.map(f -> f.getSize()).orElse(0L), (friendName + "\n").getBytes(), true,
                                network, crypto, x -> {})))
                .thenApply(b -> {
                    entrie = entrie.removeEntry("/" + friendName + "/");
                    return true;
                });
    }

    public CompletableFuture<Optional<String>> getGroupUid(String groupName) {
        return getGroupNameMappings()
                .thenApply(m -> m.uidToGroupName.entrySet().stream()
                        .filter(e -> e.getValue().equals(groupName))
                        .map(e -> e.getKey())
                        .findFirst());
    }

    @JsMethod
    public CompletableFuture<Boolean> removeFollower(String usernameToRemove) {
        LOG.info("Remove follower: " + usernameToRemove);
        // remove /$us/shared/$them
        Path sharingDir = Paths.get(this.username, SHARED_DIR_NAME, usernameToRemove);
        return removeFromFriendGroup(usernameToRemove)
                .thenCompose(x1 -> removeFromFollowersGroup(usernameToRemove))
                .thenCompose(x2 -> unshareItemsInSharingFolder(usernameToRemove, usernameToRemove)) // revoke access to everything ever shared with this user!
                .thenCompose(x3 -> getSharingFolder())
                .thenCompose(sharing -> getByPath(sharingDir)
                        .thenCompose(dir -> dir.get().remove(sharing, sharingDir, this)))
                .thenApply(x4 -> true);
    }

    private CompletableFuture<Boolean> removeFromFriendGroup(String usernameToRemove) {
        return getGroupUid(SocialState.FRIENDS_GROUP_NAME)
                .thenCompose(friendsUid -> friendsUid.isPresent() ?
                        removeFromGroup(friendsUid.get(), usernameToRemove) :
                        Futures.of(true));
    }

    private CompletableFuture<Boolean> removeFromFollowersGroup(String usernameToRemove) {
        return getGroupUid(SocialState.FOLLOWERS_GROUP_NAME)
                .thenCompose(followersUid -> followersUid.isPresent() ?
                        removeFromGroup(followersUid.get(), usernameToRemove) :
                        Futures.of(true));
    }

    /** Remove a user from a group. This involves rotating the keys to the group sharing dir,
     *  and then also rotating the keys for everything ever shared with the group.
     *
     * @param groupUid
     * @param username
     * @return
     */
    public CompletableFuture<Boolean> removeFromGroup(String groupUid, String username) {
        return unShareReadAccess(Paths.get(this.username, SHARED_DIR_NAME, groupUid), username)
                .thenCompose(x -> unshareItemsInSharingFolder(groupUid, username));
    }

    public CompletableFuture<Boolean> unshareItemsInSharingFolder(String folderName, String usernameToRevoke) {
        return getByPath(Paths.get(username, SHARED_DIR_NAME, folderName))
                .thenCompose(opt -> {
                    if (opt.isEmpty())
                        return Futures.of(true);
                    return CapabilityStore.loadReadAccessSharingLinksFromIndex(null, opt.get(), null,
                            network, crypto, 0, false, false)
                            .thenCompose(readCaps -> revokeAllReadCaps(readCaps.getRetrievedCapabilities(), usernameToRevoke))
                            .thenCompose(x -> CapabilityStore.loadWriteAccessSharingLinksFromIndex(null, opt.get(), null,
                                    network, crypto, 0, false, false)
                                    .thenCompose(writeCaps -> revokeAllWriteCaps(writeCaps.getRetrievedCapabilities(), usernameToRevoke)));
                });
    }

    private CompletableFuture<Boolean> revokeAllReadCaps(List<CapabilityWithPath> caps, String usernameToRevoke) {
        return Futures.reduceAll(caps, true,
                (b, c) -> unShareReadAccess(Paths.get(c.path), usernameToRevoke),
                (a, b) -> a && b);
    }

    private CompletableFuture<Boolean> revokeAllWriteCaps(List<CapabilityWithPath> caps, String usernameToRevoke) {
        return Futures.reduceAll(caps, true,
                (b, c) -> unShareWriteAccess(Paths.get(c.path), usernameToRevoke),
                (a, b) -> a && b);
    }

    public CompletableFuture<Snapshot> cleanPartialUploads() {
        TransactionService txns = getTransactionService();
        return getUserRoot().thenCompose(home -> network.synchronizer
                .applyComplexUpdate(home.owner(), txns.getSigner(),
                        (s, comitter) -> txns.clearAndClosePendingTransactions(s, comitter)));
    }

    public void logout() {
        entrie = TrieNodeImpl.empty();
    }

    @JsMethod
    public CompletableFuture<List<ServerMessage>> getNewMessages() {
        //get all messages not dismissed
        return network.serverMessager.getMessages(username, signer.secret);
    }

    @JsMethod
    public CompletableFuture<List<ServerConversation>> getServerConversations() {
        if (this.username == null) {
            return Futures.of(Collections.emptyList());
        }
        return network.serverMessager.getMessages(username, signer.secret).thenApply(ServerConversation::combine);
    }

    @JsMethod
    public CompletableFuture<Boolean> dismissMessage(ServerMessage message) {
        ServerMessage dismiss = new ServerMessage(message.id, ServerMessage.Type.Dismiss, System.currentTimeMillis(), "", Optional.empty(), true);
        return network.serverMessager.sendMessage(username, dismiss, signer.secret);
    }

    @JsMethod
    public CompletableFuture<Boolean> sendReply(ServerMessage prior, String message) {
        ServerMessage msg = new ServerMessage(prior.id, ServerMessage.Type.FromUser, System.currentTimeMillis(), message, Optional.of(prior.id), true);
        return network.serverMessager.sendMessage(username, msg, signer.secret);
    }

    @JsMethod
    public CompletableFuture<Boolean> sendFeedback(String message) {
        ServerMessage msg = ServerMessage.buildUserMessage(message);
        return network.serverMessager.sendMessage(username, msg, signer.secret);
    }

    public static <V> CompletableFuture<V> time(Supplier<CompletableFuture<V>> f, String name) {
        long t0 = System.currentTimeMillis();
        return f.get().thenApply(x -> {
            long t1 = System.currentTimeMillis();
            LOG.log(Level.INFO, name + " took " + (t1 - t0) + "ms");
            return x;
        });
    }
}
