import java.util.Arrays;

/*
 * Java Implementation of SHA3
 * References:
 * SHA3 Implementation by Markku-Juhani: https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * NIST Special Publication 800-185: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
 * @author Kannika Armstrong, and Sam Viet Huynh
 * @version Spring 2022
 */

public class Sha3 {

    // State context: State instance fields
    // Stores byte size to manipulate security level call.
    // In SHA-3, intermediate state sizes from w = 8, 200 bits
    private static final int SIZE = 200;
    // Initializes array to hold 200 bytes, stores data, length, and padding. (Sponge array)
    byte[] st_b = new byte[SIZE];
    private int pt;
    private int rsiz;
    private static int mdlen;		// these don't overflow
    // Iterative construction: 24 rounds constants
    private static final int KECCAKF_ROUNDS = 24;;

    private boolean ext = false, kmac = false;
    private static final byte[] KMAC_N = {(byte)0x4B, (byte)0x4D, (byte)0x41, (byte)0x43}; // "KMAC" in ASCII
    private static final byte[] right_encode_0 = {(byte)0x00, (byte)0x01}; // right_encode(0)

    // Representations of the constants; to populate 'RC' round contant array on radix 16
    private static final long[] keccakf_rndc = new long[] {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    // Initialize keccak fields and constants
    private static final int[] keccakf_rotc = new int[] {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

    private static final int[] keccakf_piln = new int[] {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

    // Keccak transform: 'rotate' with shifts
    private long ROTL64(long l, int i) {
        return (l << i) | (l >>> (64 - i));
    }

    /**
     * he Keccak-𝑓 permutation
     * Iterative construction: 24 rounds, each consisting of a sequence of 5 steps applied to the internal state:
     * theta (𝜃), rho (𝜌), pi (𝜋), chi (𝜒), and iota (𝜄).
     * @param b, the byte array
     * @author Kannika Armstrong, and Sam Viet Huynh
     */
    private void sha3_keccakf(byte[] b) {
        long[] st = new long[25]; // 64-bit words
        long[] bc = new long[5];

        // Converts the state for endianness before keccak operations.
        // https://stackoverflow.com/questions/1026761/how-to-convert-a-byte-array-to-its-numeric-value-java
        for (int i = 0; i < 25; i++) {
            int j = i * 8;
            st[i] = (((long)b[j] & 0xFFL))           |
                    (((long)b[j + 1] & 0xFFL) <<  8) |
                    (((long)b[j + 2] & 0xFFL) << 16) |
                    (((long)b[j + 3] & 0xFFL) << 24) |
                    (((long)b[j + 4] & 0xFFL) << 32) |
                    (((long)b[j + 5] & 0xFFL) << 40) |
                    (((long)b[j + 6] & 0xFFL) << 48) |
                    (((long)b[j + 7] & 0xFFL) << 56);
        }

        // The actual iteration for 24 rounds
        for (int r = 0; r < KECCAKF_ROUNDS; r++) {

            // theta (𝜃): linearly combines bits
            for (int i = 0; i < 5; i++) {
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
            }

            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    st[j + i] ^= t;
                }
            }

            // pi & rho
            // pi (𝜋): permutes bits within slices (planes orthogonal to lanes).
            // rho (𝜌): cyclically shifts bits within individual lanes.
            long t = st[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                bc[0] = st[j];
                st[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            // chi (𝜒): mixes highly nonlinear the bits within each row.
            for (int j = 0; j < 25; j += 5) {
                System.arraycopy(st, j, bc, 0, 5);
                for (int i = 0; i < 5; i++) {
                    st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            // iota (𝜄): adds asymmetric, round-specific constants to the (0,0) lane
            st[0] ^= keccakf_rndc[r];
        }

        // Return state to big endian after keccak operations.
        // https://stackoverflow.com/questions/1026761/how-to-convert-a-byte-array-to-its-numeric-value-java
        for (int i = 0; i < 25; i++) {
            int j = i * 8;
            long t = st[i];
            b[j] = (byte) (t & 0xFF);
            b[j + 1] = (byte) ((t >> 8) & 0xFF);
            b[j + 2] = (byte) ((t >> 16) & 0xFF);
            b[j + 3] = (byte) ((t >> 24) & 0xFF);
            b[j + 4] = (byte) ((t >> 32) & 0xFF);
            b[j + 5] = (byte) ((t >> 40) & 0xFF);
            b[j + 6] = (byte) ((t >> 48) & 0xFF);
            b[j + 7] = (byte) ((t >> 56) & 0xFF);
        }
    }

    // Constructor and initial state
    public Sha3() {}

    // Constructor: Set up initial conditions for SHA3 construct.
    public Sha3(int m) {
        Arrays.fill(this.st_b, (byte) 0);
        mdlen = m;
        this.rsiz = SIZE - 2 * m;
        this.pt = 0;
    }

    /**
     * Update the SHAKE256 sponge with a byte-oriented data chunk.
     * @param data, input
     * @param len, the length of the data
     * @author Kannika Armstrong, and Sam Viet Huynh
     */
    public void SHAKE256_update(byte[] data, int len) {
        int j = this.pt;
        for (int i = 0; i < len; i++) {
            this.st_b[j++] ^= data[i];
            if (j >= this.rsiz) {
                sha3_keccakf(st_b);
                j = 0;
            }
        }
        this.pt = j;
    }

    /**
     * Switch from absorbing to extensible squeezing.
     * @param c
     * @author Kannika Armstrong, and Sam Viet Huynh
     */
    public void SHAKE256_xof(boolean c) {
        if (c)
            st_b[pt] ^= 0x04;
        else
            st_b[pt] ^= 0x1F;
        st_b[rsiz - 1] ^= (byte) 0x80;
        sha3_keccakf(st_b);
        pt = 0;
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Repeat as many times as needed to extract the total desired number of bytes.
     * @param out
     * @param len
     * @author Kannika Armstrong, and Sam Viet Huynh
     */
    public void SHAKE_out(byte[] out, int len) {
        int j = pt;
        for (int i = 0; i < len; i++) {
            if (j >= rsiz) {
                sha3_keccakf(st_b);
                j = 0;
            }
            out[i] = st_b[j++];
        }
        pt = j;
    }
}
