using System.Security.Cryptography;
using System.Text.Json;
using SelectiveEncryption;

public class TextEncryptorTests
{
    const string Password = "Test#123";

    static string Roundtrip(string text, string extension, out string encrypted)
    {
        encrypted = TextEncryptor.Encrypt(text, TextEncryptor.Analyze(text, extension), Password);
        return TextEncryptor.Decrypt(encrypted, Password);
    }

    [Fact]
    public void Text_is_restored_exactly_and_only_secrets_change()
    {
        string text = "الاسم: أحمد\r\nرقم الهاتف: 0770 123 4567\r\nPassword: Ahmed@2024\r\nNothing secret here.";
        string restored = Roundtrip(text, ".txt", out string encrypted);

        Assert.Equal(text, restored);
        Assert.DoesNotContain("0770 123 4567", encrypted);
        Assert.DoesNotContain("Ahmed@2024", encrypted);
        Assert.Contains("الاسم: أحمد", encrypted);            // not sensitive -> unchanged
        Assert.Contains("Nothing secret here.", encrypted);
        Assert.Equal(2, TextEncryptor.TokenPattern.Matches(encrypted).Count);
    }

    [Fact]
    public void Wrong_password_fails()
    {
        string text = "a.b@example.com";
        string encrypted = TextEncryptor.Encrypt(text, Detector.Find(text), Password);
        Assert.Throws<CryptographicException>(() => TextEncryptor.Decrypt(encrypted, "wrong"));
    }

    [Fact]
    public void Csv_sensitive_columns_are_encrypted_and_csv_stays_valid()
    {
        string csv = "id,name,salary,national_id\n1,Ali,1500000,199012345678\n2,Sara,1250000,199145678901\n";
        string restored = Roundtrip(csv, ".csv", out string encrypted);

        Assert.Equal(csv, restored);
        Assert.Contains("1,Ali,[[ENC:SALARY:", encrypted);
        Assert.DoesNotContain("1500000", encrypted);
        foreach (string line in encrypted.TrimEnd().Split('\n'))
            Assert.Equal(4, line.Split(',').Length);           // still 4 columns on every line
    }

    [Fact]
    public void Json_stays_valid_json()
    {
        string json = "{ \"user\": \"sara.m@example.com\", \"password\": \"S@ra!\", \"port\": 8080 }";
        string restored = Roundtrip(json, ".json", out string encrypted);

        Assert.Equal(json, restored);
        using var doc = JsonDocument.Parse(encrypted);         // throws if the JSON is broken
        Assert.StartsWith("[[ENC:EMAIL:", doc.RootElement.GetProperty("user").GetString());
        Assert.Equal(8080, doc.RootElement.GetProperty("port").GetInt32());
    }

    [Fact]
    public void Only_checked_items_are_encrypted()
    {
        string text = "a.b@example.com 0770 123 4567";
        var onlyPhone = Detector.Find(text).Where(f => f.Type == "PHONE");
        string encrypted = TextEncryptor.Encrypt(text, onlyPhone, Password);
        Assert.StartsWith("a.b@example.com [[ENC:PHONE:", encrypted);
    }
}
