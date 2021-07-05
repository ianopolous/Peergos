package peergos.server.tests.simulation;

import peergos.server.simulation.AccessControl;
import peergos.server.simulation.FileSystem;
import peergos.server.simulation.Stat;
import peergos.shared.user.fs.FileProperties;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class NativeFileSystemImpl implements FileSystem {

    private final Path root;
    private final String user;
    private final AccessControl accessControl;

    public NativeFileSystemImpl(Path root, String user, AccessControl accessControl) {
        this.root = root;
        this.user = user;
        this.accessControl =  accessControl;
        init();
    }

    private void init() {
        Path userRoot = Paths.get("/" + user);

        for (Path path : Arrays.asList(
                userRoot
//                , sharedRoot,
//                peergosShare
        )) {
            mkdir(path);
        }

    }

    @Override
    public String user() {
        return user;
    }

    private void ensureCan(Path path, Permission permission) {
        ensureCan(path, permission, user());
    }

    private void ensureCan(Path path, Permission permission, String user) {
        Path nativePath = virtualToNative(path);
        if (! Files.exists(nativePath) && permission == Permission.READ)
            throw new IllegalStateException("Cannot read "+ path +" : native file "+ nativePath + " does not exist.");

        if (! accessControl.can(path, user, permission))
            throw new IllegalStateException("User " + user() +" not permitted to "+ permission + " " + path);
    }

    @Override
    public byte[] read(Path path, Consumer<Long> pc) {
        Path nativePath = virtualToNative(path);
        ensureCan(path, Permission.READ);
        try {
            return Files.readAllBytes(nativePath);
        } catch (IOException ioe) {
            throw new IllegalStateException(ioe);
        }
    }

    @Override
    public void write(Path path, byte[] data, Consumer<Long> progressConsumer) {

        Path nativePath = virtualToNative(path);
        ensureCan(path.getParent(), Permission.READ);
        ensureCan(path, Permission.WRITE);
        try {
            Files.write(nativePath, data);
        } catch (IOException ioe) {
            throw new IllegalStateException(ioe);
        }
    }

    @Override
    public void modify(Path path, byte[] data, Consumer<Long> progressConsumer) {
        Path nativePath = virtualToNative(path);
        ensureCan(path, Permission.WRITE);
        try {
            Files.write(nativePath, data);
        } catch (IOException ioe) {
            throw new IllegalStateException(ioe);
        }
    }

    @Override
    public void delete(Path path) {
        ensureCan(path, Permission.WRITE);

        walk(path, p -> {
                try {
                    Files.delete(virtualToNative(p));
                } catch (IOException ioe) {
                    throw new IllegalStateException(ioe);
                }
                accessControl.remove(p);
        });

    }

    private boolean isOwner(Path path) {
        return user().equals(AccessControl.getOwner(path));
    }

    @Override
    public void grant(Path path, String otherUser, FileSystem.Permission permission) {
        if (! isOwner(path))
            throw new IllegalStateException();
        accessControl.add(path, otherUser, permission);
    }

    @Override
    public void revoke(Path path, String user, FileSystem.Permission permission) {
        if (! isOwner(path))
            throw new IllegalStateException();

        accessControl.remove(path, user, permission);
    }

    @Override
    public Stat stat(Path path) {
        return new Stat() {
            @Override
            public String user() {
                return user;
            }

            @Override
            public FileProperties fileProperties() {
                File file = virtualToNative(path).toFile();

                long length = file.length();

                file.lastModified();
                if (Integer.MAX_VALUE < length)
                    throw new IllegalStateException("Large files not supported");
                int sizeLo = (int) length;
                int sizeHi = 0;

                LocalDateTime lastModified = LocalDateTime.ofInstant(Instant.ofEpochSecond(file.lastModified() / 1000),
                        ZoneOffset.systemDefault());

                // These things are a bit awkward, not supporting them for now
                Optional<byte[]> thumbnail = Optional.empty();
                boolean isHidden = false;
                String mimeType="NOT_SUPPORTED";

                //TODO make files use the new format with a stream secret
                Optional<byte[]> streamSecret = file.isDirectory() ? Optional.empty() : Optional.empty();
                return new FileProperties(file.getName(), file.isDirectory(), false, mimeType, sizeHi, sizeLo, lastModified,
                        isHidden, thumbnail, streamSecret);

            }

            @Override
            public boolean isReadable() {
                return accessControl.can(path, user(), Permission.READ);
            }

            @Override
            public boolean isWritable() {
                return accessControl.can(path, user(), Permission.WRITE);
            }
        };
    }

    private Path virtualToNative(Path path) {
        Path relativePath = Paths.get("/").relativize(path);
        return Paths.get(root.toString(), relativePath.toString());
    }

    @Override
    public void mkdir(Path path) {
        if (! path.equals(Paths.get("/"+ user()))) {
            Path parentDir = path.getParent();
            ensureCan(parentDir, Permission.WRITE);
        }


        Path nativePath = virtualToNative(path);
        boolean mkdir = nativePath.toFile().mkdir();
        if (! mkdir)
            throw new IllegalStateException("Could not make dir "+ nativePath);
    }

    @Override
    public List<Path> ls(Path path, boolean showHidden) {
        ensureCan(path, Permission.READ);
        if (! showHidden)
            throw new IllegalStateException();

        Path nativePath = virtualToNative(path);
        try {
            return Files.list(nativePath)
                    .map(e -> path.resolve(e.getFileName().toString()))
                    .collect(Collectors.toList());

        } catch (IOException ioe) {
            throw new IllegalStateException(ioe);
        }
    }

    public static void main(String[] args) {
        System.out.println("HELO");

        Path p1 = Paths.get("/something/else");
        Path p2 = Paths.get("/another/thing");

        Path p3 = Paths.get("/").relativize(p2);
        Path p4 = Paths.get(p1.toString(), p3.toString());

        System.out.println(p4);

        Path p5 = Paths.get("/some/thing/else");
        System.out.println(p5.getName(1));

    }

    @Override
    public void follow(FileSystem other, boolean reciprocate) {
        return; // this isn't being tested... yet
    }


    @Override
    public Path getRandomSharedPath(Random random, Permission permission, String sharee) {
        return accessControl.getRandomSharedPath(random, permission, sharee);
    }

    @Override
    public List<String> getSharees(Path path, Permission permission) {
        return accessControl.get(path, permission);
    }
}
