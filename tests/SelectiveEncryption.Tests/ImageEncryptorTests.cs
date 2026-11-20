using System.Drawing;
using System.Drawing.Imaging;
using System.Security.Cryptography;
using SelectiveEncryption;

public class ImageEncryptorTests
{
    const string Password = "Test#123";

    static byte[] MakeImage(string text)
    {
        using var bitmap = new Bitmap(900, 160, PixelFormat.Format24bppRgb);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.Clear(Color.White);
            using var font = new Font("Segoe UI", 30, GraphicsUnit.Pixel);
            TextRenderer.DrawText(g, text, font, new Point(20, 50), Color.Black);
        }
        using var stream = new MemoryStream();
        bitmap.Save(stream, ImageFormat.Png);
        return stream.ToArray();
    }

    [Fact]
    public void Only_the_region_changes_and_decryption_restores_every_pixel()
    {
        byte[] original = MakeImage("Phone: 0770 123 4567");
        var region = new ImageRegion("PHONE", "0770 123 4567", new Rectangle(100, 40, 300, 60));

        byte[] encrypted = ImageEncryptor.Encrypt(original, [region], Password);
        byte[] restored = ImageEncryptor.Decrypt(encrypted, Password, out int count);

        Assert.True(ImageEncryptor.IsEncrypted(encrypted));
        Assert.False(ImageEncryptor.IsEncrypted(original));
        Assert.Equal(1, count);

        using var a = new Bitmap(new MemoryStream(original));
        using var e = new Bitmap(new MemoryStream(encrypted));
        using var b = new Bitmap(new MemoryStream(restored));
        Assert.Equal(a.GetPixel(5, 5), e.GetPixel(5, 5));          // outside the region: unchanged
        Assert.NotEqual(a.GetPixel(250, 70), e.GetPixel(250, 70)); // inside: changed (almost surely)
        for (int y = 0; y < a.Height; y++)
            for (int x = 0; x < a.Width; x++)
                Assert.Equal(a.GetPixel(x, y), b.GetPixel(x, y));    // every pixel restored
    }

    [Fact]
    public void Wrong_password_fails()
    {
        var region = new ImageRegion("CUSTOM", "x", new Rectangle(0, 0, 50, 50));
        byte[] encrypted = ImageEncryptor.Encrypt(MakeImage("x"), [region], Password);
        Assert.Throws<CryptographicException>(() => ImageEncryptor.Decrypt(encrypted, "wrong", out _));
    }

    [Fact]
    public async Task Windows_ocr_finds_sensitive_text_in_an_image()
    {
        byte[] image = MakeImage("Email: ahmed.kareem@example.com");
        var regions = await ImageEncryptor.AnalyzeAsync(image);

        var email = Assert.Single(regions);
        Assert.Equal("EMAIL", email.Type);
        Assert.True(email.Box.X > 80);                       // the word "Email:" itself stays visible
    }
}
