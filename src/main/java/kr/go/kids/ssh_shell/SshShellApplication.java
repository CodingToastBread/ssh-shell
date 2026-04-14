package kr.go.kids.ssh_shell;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
    name = "ssh-shell",
    mixinStandardHelpOptions = true,
    version = "ssh-shell 0.0.1",
    description = {
        "Interactive SSH client for containers without OpenSSH.",
        "To pass dashed flags to the remote command, quote the command",
        "(\"ls -la\") or separate with --  (ssh-shell host -- ls -la)."
    }
)
public class SshShellApplication implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "[user@]host",
        description = "Target in the form user@host or host (use -l to override user).")
    String destination;

    @Parameters(index = "1..*", paramLabel = "COMMAND", arity = "0..*",
        description = "Optional remote command; if omitted, opens an interactive shell.")
    List<String> command;

    @Option(names = {"-p", "--port"}, defaultValue = "22",
        description = "SSH port (default: ${DEFAULT-VALUE}).")
    int port;

    @Option(names = {"-l", "--login"},
        description = "Login user (if not included in the destination).")
    String login;

    @Option(names = {"-i", "--identity"},
        description = "Path to a private key file (publickey authentication).")
    Path identity;

    @Option(names = "--password", interactive = true, arity = "0..1",
        description = "Use password auth. Prompts without echo if no value is given.")
    char[] password;

    @Option(names = "--strict-host-key",
        description = "Fail if the server host key is unknown (default: trust-on-first-use).")
    boolean strictHostKey;

    @Option(names = "--known-hosts",
        description = "Path to known_hosts file (default: ~/.ssh/known_hosts).")
    Path knownHostsPath;

    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new SshShellApplication())
            .setUnmatchedOptionsArePositionalParams(true);
        System.exit(cmd.execute(args));
    }

    @Override
    public Integer call() {
        SshTarget target;
        try {
            target = SshTarget.resolve(destination, login, port);
        } catch (IllegalArgumentException e) {
            System.err.println("ssh-shell: " + e.getMessage());
            return 2;
        }

        if (command == null || command.isEmpty()) {
            System.err.println("ssh-shell: interactive shell not yet implemented; provide a remote COMMAND");
            return 2;
        }

        Path knownHosts = knownHostsPath != null
            ? knownHostsPath
            : Paths.get(System.getProperty("user.home"), ".ssh", "known_hosts");
        KnownHostsVerifier verifier = new KnownHostsVerifier(knownHosts, strictHostKey);

        try {
            return SshExec.run(target, verifier, identity, password, command);
        } catch (IOException e) {
            String msg = e.getMessage();
            System.err.println("ssh-shell: " + (msg != null ? msg : e.toString()));
            return SshExec.exitCodeForIoFailure();
        }
    }
}
