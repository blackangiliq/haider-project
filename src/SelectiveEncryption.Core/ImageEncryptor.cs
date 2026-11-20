using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace SelectiveEncryption;

/// <summary>A rectangle of an image that contains sensitive data.</summary>
public record ImageRegion(string Type, string Text, Rectangle Box);

/// <summary>
/// Selective encryption of images:
///  1. Windows OCR reads the words and their rectangles.
///  2. The text detector decides which words are sensitive.
///  3. Only the pixels inside those rectangles are encrypted with AES-256-GCM
///     (they look like random noise). The rest of the image is untouched.
///  4. The information needed to decrypt (salt, rectangles, nonces, tags) is appended
///     after the end of the PNG data. Image viewers ignore it.
/// </summary>
public static class ImageEncryptor
{
    const string Marker = "SELENC01";   // last 8 bytes of an encrypted image

    record RegionInfo(int X, int Y, int Width, int Height, string Type, byte[] Nonce, byte[] Tag);
    record Metadata(byte[] Salt, List<RegionInfo> Regions);

    /// <summary>OCR + detection: returns the rectangles that contain sensitive data.</summary>
    public static async Task<List<ImageRegion>> AnalyzeAsync(byte[] imageFile, IEnumerable<string>? customWords = null)
    {
        var regions = new List<ImageRegion>();
        foreach (var line in await WindowsOcr.ReadAsync(imageFile))
        {
            // Build the line text and remember where every word starts inside it.
            var wordStarts = new List<int>();
            var lineText = new StringBuilder();
            foreach (var word in line.Words)
            {
                wordStarts.Add(lineText.Length);
                lineText.Append(word.Text).Append(' ');
            }

            foreach (var finding in Detector.Find(lineText.ToString(), customWords))
            {
                // The rectangle of a finding = union of the rectangles of the words it covers.
                Rectangle box = line.Words
                    .Where((w, i) => wordStarts[i] < finding.End && wordStarts[i] + w.Text.Length > finding.Start)
                    .Select(w => w.Box)
                    .Aggregate(Rectangle.Union);
                box.Inflate(4, 4);   // small margin around the text

                // The same text may be read by two OCR languages: keep it only once.
                if (!regions.Any(r => r.Box.IntersectsWith(box)))
                    regions.Add(new ImageRegion(finding.Type, finding.Value, box));
            }
        }
        return regions;
    }

    /// <summary>Encrypts the pixels of the given regions. Returns a PNG file (with the metadata appended).</summary>
    public static byte[] Encrypt(byte[] imageFile, IEnumerable<ImageRegion> regions, string password)
    {
        using Bitmap bitmap = LoadRgb(imageFile, imageFile.Length);
        byte[] salt = Crypto.NewSalt();
        byte[] key = Crypto.DeriveKey(password, salt);
        var metadata = new Metadata(salt, []);

        foreach (var region in regions)
        {
            Rectangle box = Rectangle.Intersect(region.Box, new Rectangle(Point.Empty, bitmap.Size));
            if (box.IsEmpty) continue;

            byte[] pixels = ReadPixels(bitmap, box);
            var (nonce, tag, cipher) = Crypto.Encrypt(key, pixels, Label(region.Type, box));
            WritePixels(bitmap, box, cipher);   // same size as the pixels -> looks like noise
            metadata.Regions.Add(new RegionInfo(box.X, box.Y, box.Width, box.Height, region.Type, nonce, tag));
        }

        // PNG is lossless: every encrypted byte is saved exactly (JPEG would destroy them).
        using var output = new MemoryStream();
        bitmap.Save(output, ImageFormat.Png);
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(metadata);
        output.Write(json);                                  // [PNG][JSON][JSON length: 4 bytes][SELENC01]
        output.Write(BitConverter.GetBytes(json.Length));
        output.Write(Encoding.ASCII.GetBytes(Marker));
        return output.ToArray();
    }

    /// <summary>Restores the original pixels. Returns a normal PNG file.</summary>
    public static byte[] Decrypt(byte[] encryptedFile, string password, out int regionCount)
    {
        Metadata metadata = ReadMetadata(encryptedFile, out int pngLength)
            ?? throw new InvalidDataException("This image is not encrypted by this program.");

        using Bitmap bitmap = LoadRgb(encryptedFile, pngLength);
        byte[] key = Crypto.DeriveKey(password, metadata.Salt);

        // Reverse order, so overlapping regions are undone correctly.
        foreach (var r in Enumerable.Reverse(metadata.Regions))
        {
            var box = new Rectangle(r.X, r.Y, r.Width, r.Height);
            byte[] plain = Crypto.Decrypt(key, r.Nonce, r.Tag, ReadPixels(bitmap, box), Label(r.Type, box));
            WritePixels(bitmap, box, plain);
        }

        regionCount = metadata.Regions.Count;
        using var output = new MemoryStream();
        bitmap.Save(output, ImageFormat.Png);
        return output.ToArray();
    }

    public static bool IsEncrypted(byte[] file) => ReadMetadata(file, out _) != null;

    // The rectangle and type are authenticated: moving a region or changing its type breaks decryption.
    static string Label(string type, Rectangle box) => $"IMG:{type}:{box.X},{box.Y},{box.Width},{box.Height}";

    static Metadata? ReadMetadata(byte[] file, out int pngLength)
    {
        pngLength = file.Length;
        int end = file.Length - Marker.Length;
        if (end < 4 || Encoding.ASCII.GetString(file, end, Marker.Length) != Marker) return null;

        int jsonLength = BitConverter.ToInt32(file, end - 4);
        pngLength = end - 4 - jsonLength;
        return JsonSerializer.Deserialize<Metadata>(file.AsSpan(pngLength, jsonLength));
    }

    /// <summary>Loads an image as 24-bit RGB (3 bytes per pixel: Blue, Green, Red).</summary>
    static Bitmap LoadRgb(byte[] file, int length)
    {
        using var stream = new MemoryStream(file, 0, length);
        using var image = new Bitmap(stream);
        return image.Clone(new Rectangle(Point.Empty, image.Size), PixelFormat.Format24bppRgb);
    }

    /// <summary>Copies the bytes of a rectangle, row after row, into one array.</summary>
    static byte[] ReadPixels(Bitmap bitmap, Rectangle box)
    {
        BitmapData data = bitmap.LockBits(box, ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
        int rowBytes = box.Width * 3;
        byte[] pixels = new byte[rowBytes * box.Height];
        for (int y = 0; y < box.Height; y++)
            Marshal.Copy(data.Scan0 + y * data.Stride, pixels, y * rowBytes, rowBytes);
        bitmap.UnlockBits(data);
        return pixels;
    }

    /// <summary>Writes an array produced by <see cref="ReadPixels"/> back into the rectangle.</summary>
    static void WritePixels(Bitmap bitmap, Rectangle box, byte[] pixels)
    {
        BitmapData data = bitmap.LockBits(box, ImageLockMode.WriteOnly, PixelFormat.Format24bppRgb);
        int rowBytes = box.Width * 3;
        for (int y = 0; y < box.Height; y++)
            Marshal.Copy(pixels, y * rowBytes, data.Scan0 + y * data.Stride, rowBytes);
        bitmap.UnlockBits(data);
    }
}
