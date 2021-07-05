package peergos.server.simulation;

import peergos.shared.social.FollowRequestWithCipherText;
import peergos.shared.user.*;
import peergos.shared.user.fs.*;
import peergos.shared.util.ProgressConsumer;
import peergos.shared.util.Serialize;

import java.nio.file.Path;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class PeergosFileSystemImpl implements FileSystem {

    private final UserContext userContext;

    public PeergosFileSystemImpl(UserContext userContext) {
        this.userContext = userContext;
    }

    @Override
    public String user() {
        return userContext.username;
    }

    private FileWrapper getPath(Path path) {
        Optional<FileWrapper> res = userContext.getByPath(path).join();
        if (res.isEmpty()) {
            userContext.getByPath(path).join();
            throw new IllegalStateException("Unable to retrieve file at " + path);
        }
        return res.get();
    }

    private FileWrapper getDirectory(Path path) {
        return getPath(path.getParent());
    }

    @Override
    public byte[] read(Path path, Consumer<Long> progressConsumer) {
        FileWrapper wrapper = getPath(path);
        long size = wrapper.getFileProperties().size;
        ProgressConsumer<Long> monitor = (readBytes) -> progressConsumer.accept(readBytes);
        AsyncReader in = wrapper.getInputStream(userContext.network, userContext.crypto, size, monitor).join();
        return Serialize.readFully(in, size).join();
    }

    @Override
    public void write(Path path, byte[] data, Consumer<Long> progressConsumer) {
        FileWrapper directory = getDirectory(path);
        AsyncReader resetableFileInputStream = new AsyncReader.ArrayBacked(data);
        String fileName = path.getFileName().toString();
        ProgressConsumer<Long> pc  = l -> progressConsumer.accept(l);
        FileWrapper fileWrapper = directory.uploadOrReplaceFile(fileName, resetableFileInputStream, data.length,
                userContext.network, userContext.crypto, pc, userContext.crypto.random.randomBytes(32)).join();

    }

    @Override
    public void modify(Path path, byte[] data, Consumer<Long> progressConsumer) {
        FileWrapper file = getPath(path);
        file.overwriteFileJS(AsyncReader.build(data), 0, data.length,
                userContext.network, userContext.crypto, l -> progressConsumer.accept(l)).join();
    }

    @Override
    public void delete(Path path) {
        FileWrapper directory = getDirectory(path);
        FileWrapper updatedParent = getPath(path).remove(directory, path, userContext).join();
    }

    @Override
    public List<Path> ls(Path path, boolean showHidden) {
        return getPath(path).getChildren(userContext.crypto.hasher, userContext.network)
                .join()
                .stream()
                .filter(e -> showHidden || ! e.getFileProperties().isHidden)
                .map(e -> path.resolve(e.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public void grant(Path path, String user, Permission permission) {
        Set<String> userSet = Stream.of(user).collect(Collectors.toSet());
        switch (permission) {
            case READ:
                if(! userContext.shareReadAccessWith(path, userSet).join()){
                    throw new Error("unable to grant read access");
                }
                return;
            case WRITE:
                if(! userContext.shareWriteAccessWith(path, userSet).join()){
                    throw new Error("unable to grant write access");
                }
                return;
        }
        throw new IllegalStateException();
    }

    @Override
    public void revoke(Path path, String user, Permission permission) {

        switch (permission) {
            case READ:
                userContext.unShareReadAccess(path, user).join();
                return;
            case WRITE:
                userContext.unShareWriteAccess(path, user).join();
                return;
        }
        throw new IllegalStateException();
    }

    @Override
    public Stat stat(Path path) {
        FileWrapper fileWrapper = getPath(path);
        return new Stat() {
            @Override
            public boolean isReadable() {
                return fileWrapper.isReadable();
            }

            @Override
            public boolean isWritable() {
                return fileWrapper.isWritable();
            }

            @Override
            public String user() {
                return fileWrapper.getOwnerName();
            }

            @Override
            public FileProperties fileProperties() {
                return fileWrapper.getFileProperties();
            }
        };

    }

    @Override
    public void mkdir(Path path) {
        getDirectory(path).mkdir(path.getFileName().toString(),
                userContext.network,
                false,
                userContext.crypto).join();
    }

    @Override
    public void follow(FileSystem other, boolean reciprocate) {
        UserContext otherContext = ((PeergosFileSystemImpl) other).userContext;

        this.userContext.sendInitialFollowRequest(other.user()).join();
        List<FollowRequestWithCipherText> join = otherContext.processFollowRequests().join();
        FollowRequestWithCipherText req = join.stream()
                .filter(e -> e.getEntry().ownerName.equals(user()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException());
        otherContext.sendReplyFollowRequest(req, true, reciprocate).join();
        this.userContext.processFollowRequests().join();
    }

    @Override
    public Path getRandomSharedPath(Random random, Permission permission, String sharee) {
        throw new IllegalStateException("Not implemented");
    }

    @Override
    public List<String> getSharees(Path path, Permission permission) {
        FileSharedWithState sharing = userContext.sharedWith(path).join();
        switch (permission) {
            case READ:
                return new ArrayList<>(sharing.readAccess);
            case WRITE:
                return new ArrayList<>(sharing.writeAccess);
            default:
                throw new IllegalStateException();
        }
    }
}

