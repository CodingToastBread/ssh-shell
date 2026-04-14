package kr.go.kids.ssh_shell;

import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ShellFactory;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SshShellIntegrationTest {

    @TempDir
    Path tmp;

    private SshServer sshd;
    private Path userKeyFile;
    private KeyPair userKeyPair;
    private InputStream originalStdin;

    @BeforeEach
    void startServer() throws IOException {
        originalStdin = System.in;
        // MINA's stdin pump for ChannelShell needs a clean stream; Gradle's test worker stdin
        // can close mid-flight, so use an empty stream that hits EOF immediately.
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
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(hostKeyFile));
        sshd.setPublickeyAuthenticator((user, key, session) -> key.equals(userKeyPair.getPublic()));
        sshd.setShellFactory(new GreetingShellFactory());
        sshd.start();
    }

    @AfterEach
    void stopServer() throws IOException {
        if (sshd != null) sshd.stop(true);
        if (originalStdin != null) System.setIn(originalStdin);
    }

    @Test
    void interactiveShell_opensAndReceivesRemoteGreeting() throws Exception {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));

        // Non-system terminal for the test: no real tty, no raw-mode ioctls, streams
        // we control. This exercises the connect/open/pump/close lifecycle without
        // needing a terminal device.
        try (Terminal terminal = TerminalBuilder.builder()
                .system(false)
                .streams(new ByteArrayInputStream(new byte[0]), captured)
                .type("xterm-256color")
                .build()) {
            int exit = SshShell.run(
                new SshTarget("tester", "127.0.0.1", sshd.getPort()),
                AcceptAllServerKeyVerifier.INSTANCE,
                userKeyFile,
                null,
                terminal);
            assertEquals(0, exit, "shell channel should close cleanly with exit 0");
        } finally {
            System.setOut(originalOut);
        }

        String output = captured.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("remote shell says hi"),
            () -> "expected remote shell output to be forwarded, captured: <" + output + ">");
    }

    // Simple server-side shell: writes a fixed greeting and exits 0.
    static final class GreetingShellFactory implements ShellFactory {
        @Override
        public Command createShell(ChannelSession channel) {
            return new GreetingShell();
        }
    }

    static final class GreetingShell implements Command {
        private OutputStream out;
        private ExitCallback exitCallback;

        @Override public void setInputStream(InputStream in)      {}
        @Override public void setOutputStream(OutputStream o)     { this.out = o; }
        @Override public void setErrorStream(OutputStream e)      {}
        @Override public void setExitCallback(ExitCallback cb)    { this.exitCallback = cb; }

        @Override
        public void start(ChannelSession channel, Environment env) {
            Thread t = new Thread(() -> {
                try {
                    out.write("remote shell says hi\n".getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    exitCallback.onExit(0);
                } catch (Exception e) {
                    exitCallback.onExit(1, e.getMessage());
                }
            }, "greeting-shell");
            t.setDaemon(true);
            t.start();
        }

        @Override public void destroy(ChannelSession channel) {}
    }
}
