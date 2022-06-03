/*
 * The KMACXOF256
 * @author Kannika Armstrong, and Sam Viet Huynh
 * @version Spring 2022
 */

public class KMACXOF256 {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    // Calculates the KMACXOF256
    // Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
    // KMACXOF256(K, X, L, S):
    public static byte[] KMACXOF256_cal(byte[] K, byte[] X, int L, byte[] S) {
        // Validity Conditions: len(K) <22040 and 0 ≤ L and len(S) < 22040
        // 1. newX = bytepad(encode_string(K), 136) || X || right_encode(0).
        byte[] newX = concat(concat(bytepad(encode_string(K),136), X), right_encode(0));

        // 2. return cSHAKE256(newX, L, “KMAC”, S).
        return cSHAKE256(newX, L, "KMAC".getBytes(), S);
    }

    // Calculates the cSHAKE256. Returns the output of Shake or Keccak
    // Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
    // cSHAKE256(X, L, N, S):
    private static byte[] cSHAKE256(byte[] X, int L, byte[] N, byte[] S) {
        // Validity Conditions: len(N)< 22040 and len(S)< 22040
        // 1. If N = "" and S = "":
        // return SHAKE256(X, L);
        // 2. Else:
        // return KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L).
        boolean canUseCShake = false;
        Sha3 sha = new Sha3(32);
        byte[] out = new byte[L/8];
        if (N.length != 0 && S.length != 0) { // use cSHAKE
            canUseCShake = true;
            byte[] bytepad= bytepad(concat(encode_string(N), encode_string(S)), 136);
            sha.SHAKE256_update(bytepad, bytepad.length);
        }
        sha.SHAKE256_update(X, X.length);
        sha.SHAKE256_xof(canUseCShake);
        sha.SHAKE_out(out, L/8);
        return out;
    }

    ///////////////////////////////////////////////////////////
    //////////////// The Internal Functions ///////////////////
    // as specified in the NIST Special Publication 800-185 ///
    ///////////////////////////////////////////////////////////

    // Apply the NIST encode_string primitive to S.
    // Validity Conditions: 0 ≤ len(S) < 22040
    public static byte[] encode_string(byte[] S) {
        // 1. Return left_encode(len(S)) || S.
        byte[] left_encode_bytes = left_encode(S.length * 8);
        if (S.length == 0) {
            return left_encode_bytes;
        }
        return concat(left_encode_bytes, S);
    }

    public static byte[] concat(byte[] X, byte[] Y) {
        byte[] concat = new byte[X.length + Y.length];
        System.arraycopy(X, 0, concat, 0, X.length);
        if (concat.length - X.length >= 0)
            System.arraycopy(Y, 0, concat, X.length, concat.length - X.length);
        return concat;
    }

    // Provides a right-encoded byte array based on the given integer.
    private static byte[] right_encode(int x) {
        // 1. Let n be the smallest positive integer for which 2^(8n) > x.
        int n = 0;
        while (Math.pow(2,(8 * n)) < x) {
            n++;
        }

        // 2. Let x_1, x_2,…, x_n be the base-256 encoding of x satisfying:
        //    x = ∑ 2^(8(n-i))x_i, for i = 1 to n.
        byte[] byteString = new byte[n + 1];
        for (int i = 1; i <= n; i++) {
            int x_i = x >> (8 * (i-1));
            byteString[i-1] = (byte) x_i;
        }

        // 3. Let O_i = enc8(x_i), for i = 1 to n.
        // 4. Let O_n+1 = enc8(n).
        byteString[n] = (byte) n;

        // 5. Return O = O_1 || O_2 || … || O_n || O_n+1.*/
        return byteString;
    }

    // Apply the NIST left_encode primitive to x (which is typically the bit length of some string).
    public static byte[] left_encode(int x) {
        // Validity Conditions: 0 ≤ x < 22040
        // 1. Let n be the smallest positive integer for which 2^(8n) > x.
        int n = 0;
        while (Math.pow(2, 8 * n) <= x) {
            n++;
        }
        if (n == 0) {
            n = 1;
        }

        // 2. Let x1, x2, …, xn be the base-256 encoding of x satisfying:
        //      x = ∑ (2^8*(n-i)) * xi, for i = 1 to n.
        // 3. Let Oi = enc8(xi), for i = 1 to n.
        // 4. Let O0 = enc8(n).
        byte[] bytes = new byte[n + 1];
        bytes[0] = (byte) n;
        for (int i = 1; i <= n; i++) {
            int x_i = x >> (8 * (i - 1));
            bytes[i] = (byte) x_i;
        }

        // 5. Return O = O0 || O1 || … || On−1 || On.
        return bytes;
    }

    // Apply the NIST bytepad primitive to a byte array X with encoding factor w.
    public static byte[] bytepad(byte[] X, int w) {
        // Validity Conditions: w > 0
        // 1. z = left_encode(w) || X.
        byte[] left_encode_w = left_encode(w);
        byte[] z = concat(left_encode_w, X);

        // 2. while len(z) mod 8 ≠ 0:
        // z = z || 0
        // 3. while (len(z)/8) mod w ≠ 0:
        // z = z || 00000000
        int padding = w - (z.length % w);
        byte[] bytes = {
                (byte)(padding >>> 24),
                (byte)(padding >>> 16),
                (byte)(padding >>> 8),
                (byte)padding
        };

        // 4. return z.
        return concat(z, bytes);
    }

    /////////////////////////////////////////////////////////
    /////////////////// Test All Methods ////////////////////
    /////////////////////////////////////////////////////////

    private static void test_encode_string() {
        StringBuilder str = new StringBuilder();
        for (byte b: encode_string("My Tagged Application".getBytes())){
            int v = b & 0xFF;
            str.append(HEX_ARRAY[v >>> 4]);
            str.append(HEX_ARRAY[v & 0x0F]);
            str.append(" ");
        }
        String output = str.toString();
        System.out.println(" " + output +  "\n");
    }

    private static void test_left_encode() {
        StringBuilder str = new StringBuilder();
        for (byte b: left_encode(0)){
            int v = b & 0xFF;
            str.append(HEX_ARRAY[v >>> 4]);
            str.append(HEX_ARRAY[v & 0x0F]);
            str.append(" ");
        }
        String output = str.toString();
        System.out.println(" " + output +  "\n");
    }

    private static void test_right_encode() {
        StringBuilder str = new StringBuilder();
        for (byte b: right_encode(1234567899)){
            int v = b & 0xFF;
            str.append(HEX_ARRAY[v >>> 4]);
            str.append(HEX_ARRAY[v & 0x0F]);
            str.append(" ");
        }
        String output = str.toString();
        System.out.println(" " + output +  "\n");
    }

    private static void test_bytepad() {
        StringBuilder str = new StringBuilder();
        for (byte b: bytepad("My Tagged Application".getBytes(), 64)){
            int v = b & 0xFF;
            str.append(HEX_ARRAY[v >>> 4]);
            str.append(HEX_ARRAY[v & 0x0F]);
            str.append(" ");
        }
        String output = str.toString();
        System.out.println(" " + output +  "\n");
    }

    private static void test_KMACXOF256() {
        System.out.println("Test KMACXOF256()");
        StringBuilder str = new StringBuilder();
        for (byte b: KMACXOF256_cal("My Tagged Application".getBytes(), "".getBytes(), 512, "K".getBytes())){
            int v = b & 0xFF;
            str.append(HEX_ARRAY[v >>> 4]);
            str.append(HEX_ARRAY[v & 0x0F]);
            str.append(" ");
        }
        String output = str.toString();
        System.out.println(" " + output +  "\n");
    }

    // Use to test all methods: uncomment to test each method
    public static void main(String[] args) {
        // test_left_encode();
        // test_right_encode();
        // test_encode_string();
        // test_bytepad();
        // test_KMACXOF256();
    }
}
