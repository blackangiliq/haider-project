using System.Security.Cryptography;
using System.Text;
using SelectiveEncryption;

public class CryptoTests
{
    static readonly byte[] Key = Crypto.DeriveKey("pass", Crypto.NewSalt());

    [Fact]
    public void Encrypt_then_decrypt_returns_the_original()
    {
        byte[] plain = Encoding.UTF8.GetBytes("0770 123 4567");
        var (nonce, tag, cipher) = Crypto.Encrypt(Key, plain, "ENC:PHONE");

        Assert.Equal(plain.Length, cipher.Length);          // GCM keeps the same length
        Assert.NotEqual(plain, cipher);
        Assert.Equal(plain, Crypto.Decrypt(Key, nonce, tag, cipher, "ENC:PHONE"));
    }

    [Fact]
    public void Same_value_encrypted_twice_gives_different_ciphertext()
    {
        byte[] plain = Encoding.UTF8.GetBytes("secret");
        var a = Crypto.Encrypt(Key, plain, "x");
        var b = Crypto.Encrypt(Key, plain, "x");
        Assert.NotEqual(a.Cipher, b.Cipher);                 // random nonce every time
    }

    [Fact]
    public void Wrong_key_is_rejected()
    {
        var (nonce, tag, cipher) = Crypto.Encrypt(Key, [1, 2, 3], "x");
        byte[] otherKey = Crypto.DeriveKey("other", Crypto.NewSalt());
        Assert.Throws<CryptographicException>(() => Crypto.Decrypt(otherKey, nonce, tag, cipher, "x"));
    }

    [Fact]
    public void Modified_ciphertext_is_rejected()
    {
        var (nonce, tag, cipher) = Crypto.Encrypt(Key, [1, 2, 3], "x");
        cipher[0] ^= 1;                                      // flip one bit
        Assert.Throws<CryptographicException>(() => Crypto.Decrypt(Key, nonce, tag, cipher, "x"));
    }

    [Fact]
    public void Changed_label_is_rejected()
    {
        var (nonce, tag, cipher) = Crypto.Encrypt(Key, [1, 2, 3], "ENC:PHONE");
        Assert.Throws<CryptographicException>(() => Crypto.Decrypt(Key, nonce, tag, cipher, "ENC:EMAIL"));
    }
}
