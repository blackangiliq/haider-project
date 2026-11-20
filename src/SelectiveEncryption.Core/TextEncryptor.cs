using System.Text;
using System.Text.RegularExpressions;

namespace SelectiveEncryption;

/// <summary>
/// Selective encryption of text files (TXT, CSV, JSON, ...).
/// Each sensitive item is replaced in place by a token:
///
///     [[ENC:TYPE:BASE64]]      BASE64 = salt(16) + nonce(12) + tag(16) + ciphertext
///
/// The token holds everything needed for decryption except the password,
/// so no extra key file is needed and the file keeps its normal format.
/// </summary>
public static class TextEncryptor
{
    public static readonly Regex TokenPattern =
        new(@"\[\[ENC:(?<type>[A-Z_]+):(?<data>[A-Za-z0-9+/=]+)\]\]");

    // CSV columns whose whole cell is encrypted (their values have no fixed pattern).
    static readonly string[] SensitiveColumns =
        ["password", "salary", "national_id", "birth_date", "address",
         "كلمة_المرور", "الراتب", "رقم_الهوية", "تاريخ_الميلاد", "العنوان"];

    /// <summary>Finds what should be encrypted, taking the file format into account.</summary>
    public static List<Finding> Analyze(string text, string fileExtension, IEnumerable<string>? customWords = null)
    {
        var findings = Detector.Find(text, customWords);

        switch (fileExtension.ToLowerInvariant())
        {
            case ".csv":
                // whole cells of sensitive columns + whatever the detector found elsewhere
                var cells = SensitiveCsvCells(text).ToList();
                findings = cells.Concat(findings.Where(f => !cells.Any(f.Overlaps))).OrderBy(f => f.Start).ToList();
                break;

            case ".json":
                // only touch the inside of "string values", so the JSON stays valid
                var strings = Regex.Matches(text, @"""(?:[^""\\]|\\.)*""");
                findings = findings.Where(f => strings.Any(s => f.Start > s.Index && f.End < s.Index + s.Length)).ToList();
                break;
        }
        return findings;
    }

    /// <summary>Replaces every finding with an encrypted token. The rest of the text is not touched.</summary>
    public static string Encrypt(string text, IEnumerable<Finding> findings, string password)
    {
        byte[] salt = Crypto.NewSalt();
        byte[] key = Crypto.DeriveKey(password, salt);   // derived once per file
        var result = new StringBuilder(text);

        // Work from the end of the text to the start, so earlier positions stay correct.
        foreach (var f in findings.OrderByDescending(f => f.Start))
        {
            var (nonce, tag, cipher) = Crypto.Encrypt(key, Encoding.UTF8.GetBytes(f.Value), "ENC:" + f.Type);
            byte[] packed = [.. salt, .. nonce, .. tag, .. cipher];
            string token = $"[[ENC:{f.Type}:{Convert.ToBase64String(packed)}]]";
            result.Remove(f.Start, f.Length).Insert(f.Start, token);
        }
        return result.ToString();
    }

    /// <summary>Finds every token and puts the original value back.</summary>
    public static string Decrypt(string text, string password)
    {
        var keys = new Dictionary<string, byte[]>();   // salt -> key, so PBKDF2 runs once per salt

        return TokenPattern.Replace(text, match =>
        {
            byte[] data = Convert.FromBase64String(match.Groups["data"].Value);
            byte[] salt = data[..16], nonce = data[16..28], tag = data[28..44], cipher = data[44..];

            string saltText = Convert.ToBase64String(salt);
            if (!keys.TryGetValue(saltText, out byte[]? key))
                keys[saltText] = key = Crypto.DeriveKey(password, salt);

            byte[] plain = Crypto.Decrypt(key, nonce, tag, cipher, "ENC:" + match.Groups["type"].Value);
            return Encoding.UTF8.GetString(plain);
        });
    }

    /// <summary>Simple CSV reader (comma separated, no quoted commas) that returns the cells of sensitive columns.</summary>
    static IEnumerable<Finding> SensitiveCsvCells(string text)
    {
        string[] lines = text.Split('\n');
        string[] header = lines[0].TrimEnd('\r').Split(',');
        var columns = new Dictionary<int, string>();   // column index -> token type
        for (int i = 0; i < header.Length; i++)
        {
            string name = header[i].Trim().ToLowerInvariant();
            if (SensitiveColumns.Contains(name))
                columns[i] = Regex.IsMatch(name, "^[a-z_]+$") ? name.ToUpperInvariant() : "FIELD";
        }

        int offset = lines[0].Length + 1;                 // position of the current line in the text
        foreach (string rawLine in lines.Skip(1))
        {
            string line = rawLine.TrimEnd('\r');
            int column = 0, cellStart = 0;
            for (int i = 0; i <= line.Length; i++)
            {
                if (i < line.Length && line[i] != ',') continue;   // still inside the cell

                string cell = line[cellStart..i];
                if (columns.TryGetValue(column, out string? type) && cell.Length > 0 && !TokenPattern.IsMatch(cell))
                    yield return new Finding(type, offset + cellStart, cell.Length, cell);

                column++;
                cellStart = i + 1;
            }
            offset += rawLine.Length + 1;
        }
    }
}
