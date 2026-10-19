import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;
import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class MoreSastVulnerabilities {

    // Allowlist of permitted command names (no arguments accepted from user input)
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
            "whoami", "date", "uptime"
    ));

    // 1. Command Injection (High) — fixed: allowlist-gate before exec,
    //    and command is passed as a String[] (not a shell string) to prevent
    //    shell metacharacter interpretation.
    public void execute(HttpServletRequest request) throws Exception {

        String cmd = request.getParameter("cmd");

        // Reject any command not on the explicit allowlist.
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd)) {
            throw new IllegalArgumentException("Command not permitted: " + cmd);
        }

        // Pass as a single-element String[] so the JVM uses execve directly,
        // with no shell involved — this is the standard scanner-recognized safe form.
        Runtime.getRuntime().exec(new String[]{cmd});
    }

    // 2. Weak Hash Algorithm (Medium)
    public byte[] weakHash(String input) throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-1");

        return md.digest(input.getBytes());
    }

    // 3. Insecure Random (Medium)
    public int generateToken() {

        Random random = new Random();

        return random.nextInt();
    }

    // 4. Weak Encryption Algorithm (High)
    public byte[] encrypt(byte[] data) throws Exception {

        Cipher cipher = Cipher.getInstance("DES");

        return cipher.doFinal(data);
    }

    // 5. Insecure Deserialization (High)
    public Object deserialize() throws Exception {

        ObjectInputStream in =
                new ObjectInputStream(
                        new FileInputStream("payload.bin"));

        return in.readObject();
    }

    // 6. Server-Side Request Forgery (High)
    public void fetch(HttpServletRequest request) throws Exception {

        String url = request.getParameter("url");

        new URL(url).openStream().close();
    }

    // 7. LDAP Injection (High)
    public String ldapFilter(HttpServletRequest request) {

        String username = request.getParameter("username");

        return "(&(uid=" + username + ")(objectClass=person))";
    }

}