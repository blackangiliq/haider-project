using SelectiveEncryption;

public class DetectorTests
{
    static List<string> TypesIn(string text) => Detector.Find(text).Select(f => f.Type).ToList();

    [Theory]
    [InlineData("call 0770 123 4567 now", "0770 123 4567")]
    [InlineData("call 07701234567 now", "07701234567")]
    [InlineData("call +964 781 234 5678 now", "+964 781 234 5678")]
    [InlineData("رقم الهاتف: ٠٧٧٠١٢٣٤٥٦٧", "٠٧٧٠١٢٣٤٥٦٧")]           // Arabic-Indic digits
    public void Finds_phone_numbers(string text, string expected)
    {
        var f = Assert.Single(Detector.Find(text));
        Assert.Equal(("PHONE", expected), (f.Type, f.Value));
    }

    [Fact]
    public void Finds_email() => Assert.Equal(["EMAIL"], TypesIn("mail me: a.b@example.com"));

    [Fact]
    public void Card_needs_a_valid_Luhn_checksum()
    {
        Assert.Equal(["CARD"], TypesIn("card 4111 1111 1111 1111"));
        Assert.Empty(TypesIn("card 4111 1111 1111 1112"));   // last digit wrong
    }

    [Fact]
    public void Iban_needs_a_valid_mod97_checksum()
    {
        Assert.Equal(["IBAN"], TypesIn("IBAN: IQ98 NBIQ 8501 2345 6789 012"));
        Assert.Empty(TypesIn("IBAN: IQ98 NBIQ 8501 2345 6789 013"));
    }

    [Theory]
    [InlineData("Password: Ahmed@2024", "Ahmed@2024")]
    [InlineData("wifi pwd=Home#Net55", "Home#Net55")]
    [InlineData("كلمة المرور: Sara#2024", "Sara#2024")]
    [InlineData("\"password\": \"S@ra!\"", "S@ra!")]
    public void Only_the_password_value_is_found(string text, string expected)
    {
        var f = Assert.Single(Detector.Find(text));
        Assert.Equal(("PASSWORD", expected), (f.Type, f.Value));
    }

    [Fact]
    public void National_id_needs_a_keyword()
    {
        Assert.Equal(["NATIONAL_ID"], TypesIn("رقم الهوية: 199012345678"));
        Assert.Empty(TypesIn("order 199012345678"));          // 12 digits alone are not enough
    }

    [Fact]
    public void Finds_valid_ip_only()
    {
        Assert.Equal(["IP"], TypesIn("server 192.168.1.20"));
        Assert.Empty(TypesIn("server 999.168.1.20"));
    }

    [Fact]
    public void Custom_words_are_found_ignoring_case()
    {
        var f = Assert.Single(Detector.Find("Project ORION starts soon", ["orion"]));
        Assert.Equal(("CUSTOM", "ORION"), (f.Type, f.Value));
    }

    [Fact]
    public void Normal_text_has_no_findings() =>
        Assert.Empty(Detector.Find("The meeting is on Sunday at 10 in room 4."));

    [Fact]
    public void Encrypted_tokens_are_not_detected_again()
    {
        string text = "mail a.b@example.com";
        string encrypted = TextEncryptor.Encrypt(text, Detector.Find(text), "p");
        Assert.Empty(Detector.Find(encrypted));
    }
}
