package kr.go.kids.ssh_shell;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
    name = "ssh-shell",
    mixinStandardHelpOptions = true,
    version = "ssh-shell 0.0.1",
    description = "Interactive SSH client for containers without OpenSSH."
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
        description = "Fail if the server host key is unknown (default: warn-then-accept).")
    boolean strictHostKey;

    public static void main(String[] args) {
        System.exit(new CommandLine(new SshShellApplication()).execute(args));
    }

    @Override
    public Integer call() {
        // TODO next iteration:
        //   1) parse destination into user/host
        //   2) build SshClient, connect, authenticate (publickey if -i, password if --password)
        //   3) host key policy per --strict-host-key
        //   4) command == null  -> ChannelShell + PTY + JLine raw-mode pump + SIGWINCH
        //      command != null  -> ChannelExec + stdin/stdout/stderr forward + exit status
        System.err.println("[scaffold] target=" + destination
            + (command == null ? " (interactive)" : " exec=" + command));
        return 0;
    }
}
