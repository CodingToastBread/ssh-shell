package kr.go.kids.ssh_shell;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class SshTargetTest {

    @Test
    void plainHost_usesLoginOverride() {
        SshTarget t = SshTarget.resolve("example.com", "alice", 22);
        assertEquals("alice", t.user());
        assertEquals("example.com", t.host());
        assertEquals(22, t.port());
    }

    @Test
    void userInDestination_winsOverLoginOverride() {
        SshTarget t = SshTarget.resolve("bob@example.com", "alice", 2222);
        assertEquals("bob", t.user());
        assertEquals("example.com", t.host());
        assertEquals(2222, t.port());
    }

    @Test
    void plainHost_noLogin_fallsBackToSystemUser() {
        String sys = System.getProperty("user.name");
        assumeTrue(sys != null && !sys.isBlank());
        SshTarget t = SshTarget.resolve("example.com", null, 22);
        assertEquals(sys, t.user());
    }

    @Test
    void blankLoginOverride_fallsBackToSystemUser() {
        String sys = System.getProperty("user.name");
        assumeTrue(sys != null && !sys.isBlank());
        SshTarget t = SshTarget.resolve("example.com", "   ", 22);
        assertEquals(sys, t.user());
    }

    @Test
    void blankDestination_rejected() {
        assertThrows(IllegalArgumentException.class,
            () -> SshTarget.resolve("   ", "alice", 22));
    }

    @Test
    void emptyUser_rejected() {
        assertThrows(IllegalArgumentException.class,
            () -> SshTarget.resolve("@host", "alice", 22));
    }

    @Test
    void emptyHost_rejected() {
        assertThrows(IllegalArgumentException.class,
            () -> SshTarget.resolve("user@", "alice", 22));
    }

    @Test
    void portInDestination_rejectedWithHint() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> SshTarget.resolve("alice@host:2222", null, 22));
        assertTrue(ex.getMessage().contains("-p"));
    }

    @Test
    void multipleAt_rejected() {
        assertThrows(IllegalArgumentException.class,
            () -> SshTarget.resolve("a@b@c", null, 22));
    }

    @Test
    void portOutOfRange_rejected() {
        assertThrows(IllegalArgumentException.class,
            () -> SshTarget.resolve("host", "alice", 0));
        assertThrows(IllegalArgumentException.class,
            () -> SshTarget.resolve("host", "alice", 70000));
    }
}
