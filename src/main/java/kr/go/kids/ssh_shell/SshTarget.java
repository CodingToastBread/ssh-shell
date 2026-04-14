package kr.go.kids.ssh_shell;

public record SshTarget(String user, String host, int port) {

    public SshTarget {
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("host must not be blank");
        }
        if (user == null || user.isBlank()) {
            throw new IllegalArgumentException("user must not be blank");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
    }

    public static SshTarget resolve(String destination, String loginOverride, int port) {
        if (destination == null || destination.isBlank()) {
            throw new IllegalArgumentException("destination must not be blank");
        }

        int at = destination.indexOf('@');
        String destUser = at >= 0 ? destination.substring(0, at) : null;
        String host     = at >= 0 ? destination.substring(at + 1) : destination;

        if (destUser != null && destUser.isEmpty()) {
            throw new IllegalArgumentException("empty user in destination: '" + destination + "'");
        }
        if (host.isEmpty()) {
            throw new IllegalArgumentException("empty host in destination: '" + destination + "'");
        }
        if (host.contains("@")) {
            throw new IllegalArgumentException("multiple '@' in destination: '" + destination + "'");
        }
        if (host.contains(":")) {
            throw new IllegalArgumentException(
                "port must be provided via -p, not embedded in destination: '" + destination + "'");
        }

        String user = destUser != null ? destUser
                    : loginOverride != null && !loginOverride.isBlank() ? loginOverride
                    : System.getProperty("user.name");
        if (user == null || user.isBlank()) {
            throw new IllegalArgumentException("could not determine login user; pass -l <user>");
        }

        return new SshTarget(user, host, port);
    }
}
