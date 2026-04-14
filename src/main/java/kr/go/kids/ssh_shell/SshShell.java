package kr.go.kids.ssh_shell;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.jline.terminal.Attributes;
import org.jline.terminal.Size;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;

final class SshShell {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration AUTH_TIMEOUT    = Duration.ofSeconds(15);
    private static final Duration CHANNEL_TIMEOUT = Duration.ofSeconds(15);

    private static final int EXIT_USAGE       = 2;
    private static final int EXIT_SSH_FAILURE = 255;

    private SshShell() {}

    // Production entry point: owns a system JLine terminal and puts it into raw mode.
    static int run(SshTarget target,
                   ServerKeyVerifier hostKeyVerifier,
                   Path identity,
                   char[] password) throws IOException {
        try (Terminal terminal = TerminalBuilder.builder()
                .system(true)
                .nativeSignals(true)
                .build()) {
            return run(target, hostKeyVerifier, identity, password, terminal);
        }
    }

    // Overload that takes an externally-managed Terminal so tests can inject a
    // non-system (dumb) terminal with canned streams.
    static int run(SshTarget target,
                   ServerKeyVerifier hostKeyVerifier,
                   Path identity,
                   char[] password,
                   Terminal terminal) throws IOException {
        if (identity == null && password == null) {
            System.err.println("ssh-shell: no authentication method; pass -i <private-key> or --password");
            return EXIT_USAGE;
        }
        if (identity != null && !Files.isReadable(identity)) {
            System.err.println("ssh-shell: cannot read private key file: " + identity);
            return EXIT_USAGE;
        }

        try (SshClient client = SshClient.setUpDefaultClient()) {
            client.setServerKeyVerifier(hostKeyVerifier);
            client.start();

            try (ClientSession session = client.connect(target.user(), target.host(), target.port())
                    .verify(CONNECT_TIMEOUT)
                    .getSession()) {

                if (identity != null) {
                    session.setKeyIdentityProvider(new FileKeyPairProvider(identity));
                }
                if (password != null) {
                    String pw = new String(password);
                    Arrays.fill(password, '\0');
                    session.addPasswordIdentity(pw);
                }
                session.auth().verify(AUTH_TIMEOUT);

                return openShellAndPump(session, terminal);
            }
        }
    }

    private static int openShellAndPump(ClientSession session, Terminal terminal) throws IOException {
        Size size = terminal.getSize();
        String termType = terminal.getType();
        if (termType == null || termType.isBlank() || "dumb".equals(termType)) {
            termType = "xterm-256color";
        }
        int cols = Math.max(1, size.getColumns());
        int rows = Math.max(1, size.getRows());

        try (ChannelShell channel = session.createShellChannel()) {
            channel.setPtyType(termType);
            channel.setPtyColumns(cols);
            channel.setPtyLines(rows);
            channel.setEnv("TERM", termType);

            channel.setIn(System.in);
            channel.setOut(System.out);
            channel.setErr(System.err);

            Attributes originalAttrs = terminal.enterRawMode();
            try {
                terminal.handle(Terminal.Signal.WINCH, s -> {
                    Size ns = terminal.getSize();
                    try {
                        channel.sendWindowChange(
                            Math.max(1, ns.getColumns()),
                            Math.max(1, ns.getRows()));
                    } catch (IOException ignored) {
                        // benign: channel may already be closing
                    }
                });

                channel.open().verify(CHANNEL_TIMEOUT);
                channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), Duration.ofDays(1));

                Integer status = channel.getExitStatus();
                return status != null ? status : 0;
            } finally {
                terminal.setAttributes(originalAttrs);
            }
        }
    }

    static int exitCodeForIoFailure() {
        return EXIT_SSH_FAILURE;
    }
}
