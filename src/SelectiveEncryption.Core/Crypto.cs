using System.Security.Cryptography;
using System.Text;

namespace SelectiveEncryption;

/// <summary>
/// All cryptography of the project lives here:
///  - PBKDF2-SHA256 turns a password + random salt into a 256-bit key.
///  - AES-256-GCM encrypts the data and produces a tag that detects any modification.
/// </summary>
public static class Crypto
{
    public const int SaltSize = 16;          // bytes, random for every encryption run
    public const int NonceSize = 12;         // bytes, random for every encrypted item
    public const int TagSize = 16;           // bytes, the GCM authentication tag
    public const int KeySize = 32;           // bytes = 256 bits (AES-256)
    public const int Iterations = 600_000;   // PBKDF2 rounds (OWASP recommendation)

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    /// <summary>Password + salt  ->  256-bit key (slow on purpose, to resist guessing).</summary>
    public static byte[] DeriveKey(string password, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, KeySize);

    /// <summary>
    /// Encrypts <paramref name="plain"/>. The <paramref name="label"/> is not secret but is
    /// authenticated (AES-GCM "associated data"): changing it later makes decryption fail.
    /// The ciphertext has exactly the same length as the plain data.
    /// </summary>
    public static (byte[] Nonce, byte[] Tag, byte[] Cipher) Encrypt(byte[] key, byte[] plain, string label)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] tag = new byte[TagSize];
        byte[] cipher = new byte[plain.Length];
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(label));
        return (nonce, tag, cipher);
    }

    /// <summary>Reverses <see cref="Encrypt"/>. Fails if the password is wrong or the data was changed.</summary>
    public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] tag, byte[] cipher, string label)
    {
        byte[] plain = new byte[cipher.Length];
        using var aes = new AesGcm(key, TagSize);
        try
        {
            aes.Decrypt(nonce, cipher, tag, plain, Encoding.UTF8.GetBytes(label));
        }
        catch (AuthenticationTagMismatchException)
        {
            throw new CryptographicException("Wrong password, or the encrypted data was modified.");
        }
        return plain;
    }
}
