using System.Drawing;
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;

namespace SelectiveEncryption;

/// <summary>A word read from an image, with its rectangle in pixels.</summary>
public record OcrWord(string Text, Rectangle Box);

/// <summary>A line of words, read by the OCR engine of one language.</summary>
public record OcrTextLine(string Language, List<OcrWord> Words)
{
    public string Text => string.Join(" ", Words.Select(w => w.Text));
}

/// <summary>
/// Reads text from images with the OCR engine built into Windows 10/11 (Windows.Media.Ocr).
/// No internet and no extra library are needed. Every installed OCR language is used
/// (on this machine: English + Arabic).
/// </summary>
public static class WindowsOcr
{
    public static IEnumerable<string> Languages =>
        OcrEngine.AvailableRecognizerLanguages.Select(l => l.LanguageTag);

    public static async Task<List<OcrTextLine>> ReadAsync(byte[] imageFile)
    {
        // 1) decode the image file (PNG/JPG/BMP) into a Windows SoftwareBitmap,
        //    enlarged 2x: the OCR engine reads small or very sharp text much better that way.
        using var stream = new MemoryStream(imageFile).AsRandomAccessStream();
        var decoder = await BitmapDecoder.CreateAsync(stream);
        double scale = Math.Min(2.0, OcrEngine.MaxImageDimension / (double)Math.Max(decoder.PixelWidth, decoder.PixelHeight));
        var enlarge = new BitmapTransform
        {
            ScaledWidth = (uint)(decoder.PixelWidth * scale),
            ScaledHeight = (uint)(decoder.PixelHeight * scale),
            InterpolationMode = BitmapInterpolationMode.Fant,
        };
        using var bitmap = await decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied,
            enlarge, ExifOrientationMode.IgnoreExifOrientation, ColorManagementMode.DoNotColorManage);

        // 2) run the OCR engine of every installed language (English first)
        var lines = new List<OcrTextLine>();
        foreach (var language in OcrEngine.AvailableRecognizerLanguages.OrderBy(l => l.LanguageTag.StartsWith("en") ? 0 : 1))
        {
            var engine = OcrEngine.TryCreateFromLanguage(language);
            var result = await engine.RecognizeAsync(bitmap);

            // 3) keep every word with its rectangle, converted back to the original image size
            foreach (var line in result.Lines)
            {
                var words = line.Words.Select(w => new OcrWord(w.Text, ToRectangle(w.BoundingRect, scale))).ToList();

                // For Arabic lines the engine gives the words from left to right on the image,
                // which is the reverse of the reading order. Reverse them so "رقم الهاتف: 0781 ..."
                // is read in the right order by the detector.
                if (words.Any(w => w.Text.Any(IsArabicLetter)))
                    words.Reverse();

                lines.Add(new OcrTextLine(language.LanguageTag, words));
            }
        }
        return lines;
    }

    static bool IsArabicLetter(char c) => c >= '؀' && c <= 'ۿ';

    static Rectangle ToRectangle(Windows.Foundation.Rect r, double scale) => Rectangle.FromLTRB(
        (int)(r.X / scale), (int)(r.Y / scale),
        (int)Math.Ceiling((r.X + r.Width) / scale), (int)Math.Ceiling((r.Y + r.Height) / scale));
}
