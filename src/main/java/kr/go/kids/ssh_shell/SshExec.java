package kr.go.kids.ssh_shell;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

final class SshExec {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration AUTH_TIMEOUT    = Duration.ofSeconds(15);
    private static final Duration CHANNEL_TIMEOUT = Duration.ofSeconds(15);

    private static final int EXIT_USAGE         = 2;
    private static final int EXIT_SSH_FAILURE   = 255;
    private static final int EXIT_UNKNOWN_STATUS = 255;

    private SshExec() {}

    static int run(SshTarget target,
                   ServerKeyVerifier hostKeyVerifier,
                   Path identity,
                   char[] password,
                   List<String> command) throws IOException {
        if (identity == null && password == null) {
            System.err.println("ssh-shell: no authentication method; pass -i <private-key> or --password");
            return EXIT_USAGE;
        }
        if (identity != null && !Files.isReadable(identity)) {
            System.err.println("ssh-shell: cannot read private key file: " + identity);
            return EXIT_USAGE;
        }

        String remoteCmd = String.join(" ", command);

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
                    // addPasswordIdentity only accepts String; convert, register, then
                    // wipe the caller's char[] so the secret is not kept around longer
                    // than necessary. The interned String lingers until GC - best we
                    // can do without a char[]-aware MINA API.
                    String pw = new String(password);
                    Arrays.fill(password, '\0');
                    session.addPasswordIdentity(pw);
                }

                session.auth().verify(AUTH_TIMEOUT);

                try (ChannelExec channel = session.createExecChannel(remoteCmd)) {
                    channel.setIn(System.in);
                    channel.setOut(System.out);
                    channel.setErr(System.err);

                    channel.open().verify(CHANNEL_TIMEOUT);
                    channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), Duration.ofDays(1));

                    Integer status = channel.getExitStatus();
                    return status != null ? status : EXIT_UNKNOWN_STATUS;
                }
            }
        }
    }

    static int exitCodeForIoFailure() {
        return EXIT_SSH_FAILURE;
    }
}
