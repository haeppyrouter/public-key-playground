import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class RsaKeypairDemo {
    private static final Path KEYS_DIRECTORY = Path.of("keys");
    private static final byte[] MESSAGE = "RSA key pair test message".getBytes(StandardCharsets.UTF_8);

    private RsaKeypairDemo() {}

    public static void main(String[] args) throws Exception {
        Path keyDirectory = args.length > 0 ? Path.of(args[0]) : KEYS_DIRECTORY;
        PrivateKey privateKey = loadPrivateKey(keyDirectory.resolve("private_key.pem"));
        PublicKey publicKey = loadPublicKey(keyDirectory.resolve("public_key.pem"));

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        if (!verifier.verify(signature)) {
            throw new IllegalStateException("Signature verification failed");
        }
        System.out.println("Signature verification: PASS");

        OAEPParameterSpec oaepParameters = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        Cipher encryptor = Cipher.getInstance("RSA/ECB/OAEPPadding");
        encryptor.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameters);
        byte[] ciphertext = encryptor.doFinal(MESSAGE);

        Cipher decryptor = Cipher.getInstance("RSA/ECB/OAEPPadding");
        decryptor.init(Cipher.DECRYPT_MODE, privateKey, oaepParameters);
        byte[] plaintext = decryptor.doFinal(ciphertext);
        if (!java.util.Arrays.equals(plaintext, MESSAGE)) {
            throw new IllegalStateException("Decrypted message does not match the original");
        }
        System.out.println("Encryption/decryption: PASS");
    }

    private static PrivateKey loadPrivateKey(Path path) throws Exception {
        byte[] encoded = readPem(path, "PRIVATE KEY");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    private static PublicKey loadPublicKey(Path path) throws Exception {
        byte[] encoded = readPem(path, "PUBLIC KEY");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private static byte[] readPem(Path path, String type) throws Exception {
        String pem = Files.readString(path, StandardCharsets.US_ASCII);
        String content = pem
                .replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(content);
    }
}
