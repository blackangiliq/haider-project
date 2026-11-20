using System.Diagnostics;

namespace SelectiveEncryption;

/// <summary>Result of processing one file in a folder.</summary>
public record FileResult(string File, string Status, int Items, long Milliseconds);

/// <summary>
/// Works on whole files and folders. Chooses the text or image method
/// from the file extension. Used by the command line tool and by the folder tab.
/// </summary>
public static class FileProcessor
{
    public static readonly string[] TextExtensions = [".txt", ".csv", ".json", ".log", ".md"];
    public static readonly string[] ImageExtensions = [".png", ".jpg", ".jpeg", ".bmp"];

    public static bool IsText(string path) => TextExtensions.Contains(Path.GetExtension(path).ToLowerInvariant());
    public static bool IsImage(string path) => ImageExtensions.Contains(Path.GetExtension(path).ToLowerInvariant());

    /// <summary>Default output name: notes.txt -> notes.enc.txt -> notes.dec.txt (images are always .png).</summary>
    public static string OutputPath(string input, bool encrypt)
    {
        string folder = Path.GetDirectoryName(Path.GetFullPath(input))!;
        string name = Path.GetFileNameWithoutExtension(input);
        string extension = IsImage(input) ? ".png" : Path.GetExtension(input);
        if (name.EndsWith(".enc")) name = name[..^4];
        return Path.Combine(folder, name + (encrypt ? ".enc" : ".dec") + extension);
    }

    /// <summary>Detects and encrypts the sensitive parts of one file. Returns how many items were encrypted.</summary>
    public static async Task<int> EncryptFileAsync(string input, string output, string password, IEnumerable<string>? customWords = null)
    {
        if (IsImage(input))
        {
            byte[] image = File.ReadAllBytes(input);
            var regions = await ImageEncryptor.AnalyzeAsync(image, customWords);
            File.WriteAllBytes(output, ImageEncryptor.Encrypt(image, regions, password));
            return regions.Count;
        }

        string text = File.ReadAllText(input);
        var findings = TextEncryptor.Analyze(text, Path.GetExtension(input), customWords);
        File.WriteAllText(output, TextEncryptor.Encrypt(text, findings, password));
        return findings.Count;
    }

    /// <summary>Decrypts one file. Returns how many items were restored.</summary>
    public static int DecryptFile(string input, string output, string password)
    {
        if (IsImage(input))
        {
            byte[] image = ImageEncryptor.Decrypt(File.ReadAllBytes(input), password, out int regionCount);
            File.WriteAllBytes(output, image);
            return regionCount;
        }

        string text = File.ReadAllText(input);
        File.WriteAllText(output, TextEncryptor.Decrypt(text, password));
        return TextEncryptor.TokenPattern.Matches(text).Count;
    }

    /// <summary>
    /// Encrypts (or decrypts) every supported file of a folder and its sub-folders.
    /// The same folder structure is created in the output folder, plus a report.csv.
    /// </summary>
    public static async Task<List<FileResult>> ProcessFolderAsync(string inputFolder, string outputFolder, string password,
        bool encrypt, IEnumerable<string>? customWords = null, IProgress<FileResult>? progress = null)
    {
        var results = new List<FileResult>();
        foreach (string file in Directory.GetFiles(inputFolder, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(inputFolder, file);
            string target = Path.Combine(outputFolder, IsImage(file) ? Path.ChangeExtension(relative, ".png") : relative);
            var timer = Stopwatch.StartNew();
            FileResult result;
            try
            {
                if (!IsText(file) && !IsImage(file))
                {
                    result = new(relative, "Skipped (unsupported type)", 0, 0);
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    int items = encrypt
                        ? await EncryptFileAsync(file, target, password, customWords)
                        : DecryptFile(file, target, password);
                    result = new(relative, "OK", items, timer.ElapsedMilliseconds);
                }
            }
            catch (Exception ex)
            {
                result = new(relative, "Error: " + ex.Message, 0, timer.ElapsedMilliseconds);
            }
            results.Add(result);
            progress?.Report(result);
        }

        Directory.CreateDirectory(outputFolder);
        File.WriteAllLines(Path.Combine(outputFolder, "report.csv"),
            ["File,Status,Items,Milliseconds", .. results.Select(r => $"\"{r.File}\",\"{r.Status}\",{r.Items},{r.Milliseconds}")]);
        return results;
    }
}
