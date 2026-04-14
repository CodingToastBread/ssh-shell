package kr.go.kids.ssh_shell;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KnownHostsVerifierIntegrationTest {

    @TempDir
    Path tmp;

    private SshServer sshd;
    private Path userKeyFile;
    private KeyPair userKeyPair;
    private InputStream originalStdin;

    @BeforeEach
    void startServer() throws IOException {
        originalStdin = System.in;
        System.setIn(new ByteArrayInputStream(new byte[0]));

        Path hostKeyFile = tmp.resolve("host_key");
        userKeyFile      = tmp.resolve("user_key");

        SimpleGeneratorHostKeyProvider userGen = new SimpleGeneratorHostKeyProvider(userKeyFile);
        userGen.setAlgorithm("RSA");
        userGen.setKeySize(2048);
        userKeyPair = userGen.loadKeys(null).iterator().next();

        sshd = SshServer.setUpDefaultServer();
        sshd.setHost("127.0.0.1");
        sshd.setPort(0);
        // Pin the host key so we know what the server presents across reconnects
        SimpleGeneratorHostKeyProvider hostGen = new SimpleGeneratorHostKeyProvider(hostKeyFile);
        hostGen.setAlgorithm("RSA");
        hostGen.setKeySize(2048);
        sshd.setKeyPairProvider(hostGen);
        sshd.setPublickeyAuthenticator((user, key, session) -> key.equals(userKeyPair.getPublic()));
        sshd.setCommandFactory(new SshExecIntegrationTest.ScriptedCommandFactory());
        sshd.start();
    }

    @AfterEach
    void stopServer() throws IOException {
        if (sshd != null) sshd.stop(true);
        if (originalStdin != null) System.setIn(originalStdin);
    }

    @Test
    void tofu_addsEntryToEmptyKnownHosts_andAcceptsOnSecondConnect() throws Exception {
        Path knownHosts = tmp.resolve("known_hosts");
        KnownHostsVerifier verifier = new KnownHostsVerifier(knownHosts, false);

        // First connection: file empty, TOFU should append and accept
        assertFalse(Files.exists(knownHosts), "precondition: file must not exist yet");
        int exit1 = SshExec.run(
            new SshTarget("tester", "127.0.0.1", sshd.getPort()),
            verifier, userKeyFile, null, List.of("echo", "one"));
        assertEquals(0, exit1);
        assertTrue(Files.exists(knownHosts) && Files.size(knownHosts) > 0,
            "TOFU should have populated known_hosts");

        // Second connection with a fresh verifier reading the same file: should match, not re-append
        long sizeAfterFirst = Files.size(knownHosts);
        KnownHostsVerifier verifier2 = new KnownHostsVerifier(knownHosts, false);
        int exit2 = SshExec.run(
            new SshTarget("tester", "127.0.0.1", sshd.getPort()),
            verifier2, userKeyFile, null, List.of("echo", "two"));
        assertEquals(0, exit2);
        assertEquals(sizeAfterFirst, Files.size(knownHosts),
            "verified match should not re-append to known_hosts");
    }

    @Test
    void strictMode_refusesUnknownHost() {
        Path knownHosts = tmp.resolve("known_hosts");  // does not exist
        KnownHostsVerifier verifier = new KnownHostsVerifier(knownHosts, true);

        assertThrows(IOException.class, () -> SshExec.run(
            new SshTarget("tester", "127.0.0.1", sshd.getPort()),
            verifier, userKeyFile, null, List.of("echo", "nope")));
        assertFalse(Files.exists(knownHosts),
            "strict mode must not write to known_hosts on failure");
    }

    @Test
    void mismatchedKey_refusesConnection() throws Exception {
        // Pre-populate known_hosts with a DIFFERENT key for this host.
        // We forge an entry by writing a line with the server's address but the
        // user's public key (any non-matching key will do for this test).
        Path knownHosts = tmp.resolve("known_hosts");
        int port = sshd.getPort();
        String hostId = port == 22 ? "127.0.0.1" : "[127.0.0.1]:" + port;
        String forgedLine = hostId + " "
            + org.apache.sshd.common.config.keys.PublicKeyEntry.toString(userKeyPair.getPublic())
            + System.lineSeparator();
        Files.writeString(knownHosts, forgedLine);

        KnownHostsVerifier verifier = new KnownHostsVerifier(knownHosts, false);

        assertThrows(IOException.class, () -> SshExec.run(
            new SshTarget("tester", "127.0.0.1", port),
            verifier, userKeyFile, null, List.of("echo", "nope")));

        // Mismatch must NOT silently overwrite the existing entry
        assertEquals(forgedLine, Files.readString(knownHosts));
    }
}
