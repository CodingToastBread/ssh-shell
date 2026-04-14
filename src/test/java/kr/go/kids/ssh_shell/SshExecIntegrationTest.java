package kr.go.kids.ssh_shell;

import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.command.CommandFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SshExecIntegrationTest {

    @TempDir
    Path tmp;

    private SshServer sshd;
    private Path userKeyFile;
    private KeyPair userKeyPair;
    private ScriptedCommandFactory commandFactory;
    private InputStream originalStdin;

    @BeforeEach
    void startServer() throws IOException {
        // Gradle's test worker attaches a System.in that gets closed asynchronously,
        // which trips MINA's stdin pump and can tear down the channel before the
        // server's exit-status message is processed. Swap in an empty stream so the
        // pump sees a clean EOF immediately.
        originalStdin = System.in;
        System.setIn(new ByteArrayInputStream(new byte[0]));

        Path hostKeyFile = tmp.resolve("host_key");
        userKeyFile      = tmp.resolve("user_key");

        SimpleGeneratorHostKeyProvider userGen = new SimpleGeneratorHostKeyProvider(userKeyFile);
        userGen.setAlgorithm("RSA");
        userGen.setKeySize(2048);
        userKeyPair = userGen.loadKeys(null).iterator().next();

        commandFactory = new ScriptedCommandFactory();

        sshd = SshServer.setUpDefaultServer();
        sshd.setHost("127.0.0.1");
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(hostKeyFile));
        sshd.setPublickeyAuthenticator((user, key, session) -> key.equals(userKeyPair.getPublic()));
        sshd.setPasswordAuthenticator((user, pw, session) -> "s3cret".equals(pw));
        sshd.setCommandFactory(commandFactory);
        sshd.start();
    }

    @AfterEach
    void stopServer() throws IOException {
        if (sshd != null) {
            sshd.stop(true);
        }
        if (originalStdin != null) {
            System.setIn(originalStdin);
        }
    }

    @Test
    void publickey_happyPath_execReturnsZero_andStdoutIsForwarded() throws Exception {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            int exit = SshExec.run(
                new SshTarget("tester", "127.0.0.1", sshd.getPort()),
                AcceptAllServerKeyVerifier.INSTANCE,
                userKeyFile,
                null,
                List.of("echo", "hello"));
            assertEquals(0, exit);
        } finally {
            System.setOut(originalOut);
        }
        assertEquals("echo hello", commandFactory.lastCommand.get());
        assertTrue(
            captured.toString(StandardCharsets.UTF_8).contains("OK: echo hello"),
            () -> "expected remote stdout to be forwarded, but captured: <" + captured + ">");
    }

    @Test
    void password_happyPath_authenticatesWithoutIdentity() throws Exception {
        char[] pw = "s3cret".toCharArray();
        int exit = SshExec.run(
            new SshTarget("tester", "127.0.0.1", sshd.getPort()),
            AcceptAllServerKeyVerifier.INSTANCE,
            null,
            pw,
            List.of("echo", "pw-ok"));
        assertEquals(0, exit);
        assertEquals("echo pw-ok", commandFactory.lastCommand.get());
        // SshExec wipes the caller's char[] once the password has been registered
        assertArrayEquals(new char[]{0, 0, 0, 0, 0, 0}, pw,
            "password char[] should be zeroed after SshExec.run");
    }

    @Test
    void password_wrongPassword_surfacesAsIoException() {
        char[] pw = "wrong".toCharArray();
        assertThrows(IOException.class, () -> SshExec.run(
            new SshTarget("tester", "127.0.0.1", sshd.getPort()),
            AcceptAllServerKeyVerifier.INSTANCE,
            null,
            pw,
            List.of("echo", "nope")));
    }

    @Test
    void nonZeroRemoteExitStatusPropagates() throws Exception {
        int exit = SshExec.run(
            new SshTarget("tester", "127.0.0.1", sshd.getPort()),
            AcceptAllServerKeyVerifier.INSTANCE,
            userKeyFile,
            null,
            List.of("FAIL", "42"));
        assertEquals(42, exit);
    }

    @Test
    void authFailure_surfacesAsIoException() throws IOException {
        Path wrongKey = tmp.resolve("wrong_key");
        SimpleGeneratorHostKeyProvider gen = new SimpleGeneratorHostKeyProvider(wrongKey);
        gen.setAlgorithm("RSA");
        gen.setKeySize(2048);
        gen.loadKeys(null);

        assertThrows(IOException.class, () -> SshExec.run(
            new SshTarget("tester", "127.0.0.1", sshd.getPort()),
            AcceptAllServerKeyVerifier.INSTANCE,
            wrongKey,
            null,
            List.of("echo", "nope")));
    }

    // A command factory that records the last received command and dispatches
    // a scripted response per the command string:
    //   "FAIL <n>"  -> exit with code n (no output)
    //   otherwise   -> write "OK: <command>\n" to stdout, exit 0
    static final class ScriptedCommandFactory implements CommandFactory {
        final AtomicReference<String> lastCommand = new AtomicReference<>();

        @Override
        public Command createCommand(ChannelSession channel, String command) {
            lastCommand.set(command);
            return new ScriptedCommand(command);
        }
    }

    static final class ScriptedCommand implements Command {
        private final String command;
        private OutputStream out;
        private OutputStream err;
        private ExitCallback exitCallback;

        ScriptedCommand(String command) {
            this.command = command;
        }

        @Override public void setInputStream(InputStream in)    {}
        @Override public void setOutputStream(OutputStream o)   { this.out = o; }
        @Override public void setErrorStream(OutputStream e)    { this.err = e; }
        @Override public void setExitCallback(ExitCallback cb)  { this.exitCallback = cb; }

        @Override
        public void start(ChannelSession channel, Environment env) {
            Thread worker = new Thread(() -> {
                try {
                    if (command.startsWith("FAIL ")) {
                        int code = Integer.parseInt(command.substring("FAIL ".length()).trim());
                        exitCallback.onExit(code);
                    } else {
                        out.write(("OK: " + command + "\n").getBytes(StandardCharsets.UTF_8));
                        out.flush();
                        exitCallback.onExit(0);
                    }
                } catch (Exception e) {
                    try {
                        if (err != null) {
                            err.write(String.valueOf(e.getMessage()).getBytes(StandardCharsets.UTF_8));
                            err.flush();
                        }
                    } catch (IOException ignored) {}
                    exitCallback.onExit(1, e.getMessage());
                }
            }, "scripted-cmd");
            worker.setDaemon(true);
            worker.start();
        }

        @Override
        public void destroy(ChannelSession channel) {}
    }
}
