package kr.go.kids.ssh_shell;

import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PublicKey;
import java.util.List;

final class KnownHostsVerifier implements ServerKeyVerifier {

    private final Path file;
    private final boolean strict;

    KnownHostsVerifier(Path file, boolean strict) {
        this.file = file;
        this.strict = strict;
    }

    @Override
    public boolean verifyServerKey(ClientSession session, SocketAddress remote, PublicKey serverKey) {
        String hostId = hostId(remote);
        String fingerprint = fingerprint(serverKey);

        Match match = findMatch(hostId, serverKey);
        return switch (match) {
            case MATCH    -> true;
            case MISMATCH -> {
                printMismatchWarning(hostId, fingerprint);
                yield false;
            }
            case UNKNOWN -> {
                if (strict) {
                    System.err.println("ssh-shell: host key verification failed: '"
                        + hostId + "' not in " + file + " (strict mode)");
                    yield false;
                }
                yield trustOnFirstUse(hostId, serverKey, fingerprint);
            }
        };
    }

    private enum Match { MATCH, MISMATCH, UNKNOWN }

    private Match findMatch(String hostId, PublicKey serverKey) {
        if (!Files.exists(file)) {
            return Match.UNKNOWN;
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("ssh-shell: warning - could not read " + file + ": " + e.getMessage());
            return Match.UNKNOWN;
        }

        boolean hostSeen = false;
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("|")) continue;  // hashed entries not supported in this iteration

            String[] parts = line.split("\\s+", 3);
            if (parts.length < 3) continue;

            if (!hostMatches(parts[0], hostId)) continue;
            hostSeen = true;

            PublicKey entryKey = parseKey(parts[1] + " " + parts[2]);
            if (entryKey != null && KeyUtils.compareKeys(entryKey, serverKey)) {
                return Match.MATCH;
            }
        }
        return hostSeen ? Match.MISMATCH : Match.UNKNOWN;
    }

    private static boolean hostMatches(String patternField, String hostId) {
        for (String pattern : patternField.split(",")) {
            if (pattern.equalsIgnoreCase(hostId)) return true;
        }
        return false;
    }

    private static PublicKey parseKey(String encoded) {
        try {
            return PublicKeyEntry.parsePublicKeyEntry(encoded).resolvePublicKey(null, null, null);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean trustOnFirstUse(String hostId, PublicKey serverKey, String fingerprint) {
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            StringBuilder line = new StringBuilder(hostId).append(' ');
            PublicKeyEntry.appendPublicKeyEntry(line, serverKey);
            line.append(System.lineSeparator());
            Files.writeString(file, line.toString(), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            System.err.println("ssh-shell: added host key for " + hostId
                + " (" + fingerprint + ") to " + file);
            return true;
        } catch (IOException e) {
            System.err.println("ssh-shell: failed to update " + file + ": " + e.getMessage());
            return false;
        }
    }

    private void printMismatchWarning(String hostId, String actualFingerprint) {
        System.err.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
        System.err.println("@  WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!       @");
        System.err.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
        System.err.println("The host key for '" + hostId + "' does not match the entry in " + file + ".");
        System.err.println("Presented: " + actualFingerprint);
        System.err.println("If this change is expected, remove the stale line from " + file + " and retry.");
    }

    private static String hostId(SocketAddress addr) {
        if (addr instanceof InetSocketAddress isa) {
            String host = isa.getHostString();
            int port = isa.getPort();
            return port == 22 ? host : "[" + host + "]:" + port;
        }
        return addr.toString();
    }

    private static String fingerprint(PublicKey key) {
        try {
            return KeyUtils.getFingerPrint(key);
        } catch (Exception e) {
            return "(unknown fingerprint)";
        }
    }
}
