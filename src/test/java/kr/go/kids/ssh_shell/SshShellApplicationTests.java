package kr.go.kids.ssh_shell;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SshShellApplicationTests {

    @Test
    void helpExitsZero() {
        int exit = new CommandLine(new SshShellApplication())
            .setUnmatchedOptionsArePositionalParams(true)
            .execute("--help");
        assertEquals(0, exit);
    }

    @Test
    void doubleDashSeparatesRemoteCommandFromOptions() {
        SshShellApplication app = new SshShellApplication();
        new CommandLine(app)
            .setUnmatchedOptionsArePositionalParams(true)
            .parseArgs("user@host", "--", "ls", "-la");
        assertEquals(List.of("ls", "-la"), app.command);
    }

    @Test
    void quotedCommandPreservesSpaces() {
        SshShellApplication app = new SshShellApplication();
        new CommandLine(app)
            .setUnmatchedOptionsArePositionalParams(true)
            .parseArgs("user@host", "ls -la /tmp");
        assertEquals(List.of("ls -la /tmp"), app.command);
    }
}
