package kr.go.kids.ssh_shell;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SshShellApplicationTests {

    @Test
    void helpExitsZero() {
        int exit = new CommandLine(new SshShellApplication()).execute("--help");
        assertEquals(0, exit);
    }
}
