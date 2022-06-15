import java.math.BigInteger;

/*
 * The elliptic curve that will be implemented is known as the E521 curve (a so-called Edwards curve)
 * @author Kannika Armstrong, and Sam Viet Huynh
 * @version Spring 2022
 */

public class EllipticCurve {

    // p := 2^521 −1, a Mersenne prime defining the finite field 𝔽𝑝.
    // https://stackoverflow.com/questions/4582277/biginteger-powbiginteger
    public static final BigInteger p = BigInteger.TWO.pow(521).subtract(BigInteger.ONE);

    // d =−376014
    // curve equation: x^2 + y^2 = 1 + d x^2 y^2 with d = −376014.
    // https://javatutorialhq.com/java/math/biginteger-class/negate-method-example/
    public static final BigInteger d = new BigInteger("376014").negate();

    // The number of points 𝑛 on any Edwards curve is always a multiple of 4, and for
    // E521 that number is n := 4r, where:
    // r= 2^519 − 337554763258501705789107630418782636071904961214051226618635150085779108655765.
    public static final BigInteger r = BigInteger.TWO.pow(519).subtract(
            new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));

    // y coordinate of the curve
    private final BigInteger x;

    // y coordinate of the curve
    private final BigInteger y;

    // Initial coordinate (x,y) in a natural form -> O = (0,1)
    public EllipticCurve() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
    }

    // the constructor for passing x and y value
    public EllipticCurve(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    // getter of x
    public BigInteger getX() {
        return x;
    }

    // getter of y
    public BigInteger getY() {
        return y;
    }

    /**
     * To obtain (x,y) from x and the least significant bit of y, one has to compute
     * y = ± sqrt((1 − x^2)/(1 + 376014 * x^2) mod p.
     * y = ± sqrt((1 − x^2)/(1 - d * x^2) mod p.
     * @param x
     * @author Kannika Armstrong, and Sam Viet Huynh
     */
    public EllipticCurve(BigInteger x) {
        this.x = x;
        this.y = leastSigBitY(x);
    }

    private static BigInteger leastSigBitY(BigInteger x) {
        BigInteger numerator = BigInteger.ONE.subtract(x.pow(2));;
        BigInteger denominator = BigInteger.ONE.subtract(d.multiply(x.pow(2)));
        return sqrt(numerator.multiply(denominator.modInverse(p)), p, false);
    }

    /**
     * Compute a square root of v mod p with a specified
     * least significant bit, if such a root exists.
     *
     * @param   v   the radicand.
     * @param   p   the modulus (must satisfy p mod 4 = 3).
     * @param   lsb desired least significant bit (true: 1, false: 0).
     * @return  a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *          if such a root exists, otherwise null.
     *
     * Reference: the project instruction
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        return square(v, p, lsb);
    }

    private static BigInteger square(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * Sum of two points
     * Given any two points (x1, y1) and (x2,y2) on the curve, their sum is the point
     * (x1, y1) + (x2, y2) = ((x1y2 + y1,x2)/(1 + dx1x2y1y2), (y1y2 - x1x2)/(1 - dx1x2y1y2))
     * This is called the Edwards point addition formula.
     * @param point2,
     * @return the result off adding two points
     * @author Kannika Armstrong, and Sam Viet Huynh
     */
    public EllipticCurve sum(EllipticCurve point2) {
        return addTwoPoints(point2);
    }
    private EllipticCurve addTwoPoints(EllipticCurve point2) {
        BigInteger newNumX = x.multiply(point2.y).add(y.multiply(point2.x)).mod(p);
        BigInteger newNumY = y.multiply(point2.y).subtract(x.multiply(point2.x)).mod(p);
        BigInteger newDenX = BigInteger.ONE.add(d.multiply(x).multiply(point2.x).multiply(y).multiply(point2.y)).mod(p).modInverse(p);
        BigInteger newDenY = BigInteger.ONE.subtract(d.multiply(x).multiply(point2.x).multiply(y).multiply(point2.y)).mod(p).modInverse(p);
        BigInteger newX = newNumX.multiply(newDenX).mod(p);
        BigInteger newY = newNumY.multiply(newDenY).mod(p);
        return new EllipticCurve(newX, newY);
    }

    /**
     * Support multiplication by scalar: given a point P := (x,y) on the curve and
     * a (typically very large) integer k modulo n, you must provide a method to compute
     * the point k⋅P:= P + P + P + P + ... + P (that is, the sum of P with itself k times)
     * when k > 0, with (-k)⋅P = k⋅(−P) and 0⋅P = O when k ≤ 0.
     * @author Kannika Armstrong, and Sam Viet Huynh
     */
    public EllipticCurve mulByScalar(BigInteger scalar) {
        return multiplyByScalar(scalar);
    }

    private EllipticCurve multiplyByScalar(BigInteger scalar) {
        if (scalar.equals(BigInteger.ZERO)) {
            return new EllipticCurve(BigInteger.ZERO, BigInteger.ONE);
        }
        EllipticCurve V = new EllipticCurve(x, y);
        for (int i = scalar.bitLength() - 2; i >= 0; i--) {
            V = V.sum(V);
            if (scalar.testBit(i)) {
                V = V.sum(this);
            }
        }
        return V;
    }

    /////////////////////////////////////////////////////////
    /////////////////// Test All Methods ////////////////////
    /////////////////////////////////////////////////////////

    // Use to check the test case
    public boolean equals(EllipticCurve point2) {
        return checkEquals(point2);
    }

    private boolean checkEquals(EllipticCurve point2) {
        return this.x.equals(point2.x) && this.y.equals(point2.y);
    }

    // Test the elliptic curve: Basics on Abelian groups
    // The most essential operation in elliptic curve cryptography is the computation of
    // points of form P <- k*G given a scalar k and a point G, so it is crucial to make
    // sure the operation of multiplying a point by scalar is correct.
    //
    // The first and foremost way of promoting correctness is to ensure that the
    // implementation satisfies the arithmetic properties this operation is supposed to
    // satisfy. Thus, be sure to test if:
    public void testEllipticCurve(){
        testEC();
    }

    private void testEC() {
        // A natural form -> O = (0,1)
        EllipticCurve o = new EllipticCurve();
        System.out.println("O = (" + o.x.toString() + ", " + o.y.toString() + ")");
        System.out.println();

        // Example from the course slide: G = (4,y) on the curve
        EllipticCurve g = new EllipticCurve(new BigInteger("4"));
        System.out.println("G = (" + g.x.toString() + ", " + g.y.toString() + ")");
        System.out.println();

        // 0*G = O , O = (0,1)
        EllipticCurve g_mul_0 = g.mulByScalar(BigInteger.ZERO);
        System.out.println("0*G = (" + g_mul_0.x.toString() + ", " + g_mul_0.y.toString() + ")");
        System.out.println("0*G = O is " + g_mul_0.equals(o));
        System.out.println();

        // 1*G = G
        EllipticCurve g_mul_1 = g.mulByScalar(BigInteger.ONE);
        System.out.println("1*G = (" + g_mul_1.x.toString() + ", " + g_mul_1.y.toString() + ")");
        System.out.println("1*G = G is " + g_mul_1.equals(g));
        System.out.println();

        // 2*G = G + G
        EllipticCurve g_mul_2 = g.mulByScalar(BigInteger.TWO);
        EllipticCurve sum2g = g.sum(g);
        System.out.println("2*G = (" + g_mul_2.x.toString() + ", " + g_mul_2.y.toString() + ")");
        System.out.println("G + G = (" + sum2g.x.toString() + ", " + sum2g.y.toString() + ")");
        System.out.println("2*G = G + G is " + g_mul_2.equals(sum2g));
        System.out.println();

        // 4*G = 2*(2*G)
        EllipticCurve g_mul_4 = g.mulByScalar(new BigInteger("4"));
        EllipticCurve g_mul_2_mul_2 = g_mul_2.mulByScalar(BigInteger.TWO);
        System.out.println("4*G = (" + g_mul_4.x.toString() + ", " + g_mul_4.y.toString() + ")");
        System.out.println("2*(2*G) = (" + g_mul_2_mul_2.x.toString() + ", " + g_mul_2_mul_2.y.toString() + ")");
        System.out.println("4*G = 2*(2*G) is " + g_mul_4.equals(g_mul_2_mul_2));
        System.out.println("4*G = 2*(2*G) is " + g_mul_2_mul_2.equals(g_mul_4));

        // 4*G ≠ O
        System.out.println("4*G ≠ O is " + !g_mul_4.equals(o));

        // r*G = O
        System.out.println("r*G = O is " + g.mulByScalar(r).equals(o));
    }

    // Use to test all methods : Uncomment to run test method
    public static void main(String[] args) {
        //EllipticCurve e = new EllipticCurve();
        //e.testEllipticCurve();
    }
}
