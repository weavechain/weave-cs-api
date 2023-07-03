namespace weaveapi;

/**
 * Mimics java.util.Random
 * Given the same seed, it generates the same bytes as Java's Random
 */
public class JavaRandom
{
    private ulong _seed;

    public JavaRandom(ulong seed)
    {
        this._seed = (seed ^ 0x5DEECE66DUL) & ((1UL << 48) - 1);
    }

    public int NextInt(int n)
    {
        if (n <= 0)
            throw new ArgumentException("n must be positive");

        if ((n & -n) == n) // i.e., n is a power of 2
            return (int)((n * (long)Next(31)) >> 31);

        long bits,
            val;
        do
        {
            bits = Next(31);
            val = bits % (uint)n;
        } while (bits - val + (n - 1) < 0);

        return (int)val;
    }

    public uint Next(int bits)
    {
        _seed = (_seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);

        return (uint)(_seed >> (48 - bits));
    }
}
