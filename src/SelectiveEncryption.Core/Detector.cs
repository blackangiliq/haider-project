using System.Text.RegularExpressions;

namespace SelectiveEncryption;

/// <summary>One piece of sensitive data found inside a text.</summary>
public record Finding(string Type, int Start, int Length, string Value)
{
    public int End => Start + Length;
    public bool Overlaps(Finding other) => Start < other.End && other.Start < End;
}

/// <summary>
/// Finds sensitive data in text with regular expressions.
/// Some types are double-checked with math (Luhn for cards, MOD-97 for IBAN)
/// to avoid false alarms.
/// </summary>
public static class Detector
{
    /// <summary>
    /// A detection rule. If the pattern has a group named "v", only that group is
    /// sensitive (example: in "Password: abc" only "abc" is hidden, not the word "Password").
    /// </summary>
    record Rule(string Type, string Pattern, Func<string, bool>? IsValid = null);

    // The order matters: when two rules match the same characters, the earlier rule wins.
    static readonly Rule[] Rules =
    [
        new("EMAIL", @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        new("IBAN", @"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b", IsValidIban),
        new("CARD", @"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)", IsValidCard),
        new("PHONE", @"(?<![\d+])(?:\+964|00964|0)[ -]?7[3-9]\d(?:[ -]?\d){7}(?!\d)"),   // Iraqi mobile
        new("PHONE", @"(?<![\w+])\+\d{1,3}(?:[ -]?\d){7,12}(?!\d)"),                      // international
        new("PASSWORD", @"(?i)(?:password|passwd|pwd|كلمة\s*(?:المرور|السر)|الرمز\s*السري)[""']?\s*[:=]\s*[""']?(?<v>[^\s""',;]+)"),
        new("NATIONAL_ID", @"(?i)(?:national\s*id|id\s*number|رقم\s*الهوية|الرقم\s*الوطني)[""']?\s*[:=]?\s*[""']?(?<v>\d{12})(?!\d)"),
        new("IP", @"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"),
    ];

    public static IReadOnlyList<string> Types => Rules.Select(r => r.Type).Distinct().Append("CUSTOM").ToList();

    /// <summary>Returns all sensitive items in <paramref name="text"/>, sorted by position, never overlapping.</summary>
    /// <param name="customWords">Extra words chosen by the user (e.g. a name); they are found case-insensitively.</param>
    public static List<Finding> Find(string text, IEnumerable<string>? customWords = null)
    {
        var rules = Rules.ToList();
        foreach (string word in customWords ?? [])
            if (!string.IsNullOrWhiteSpace(word))
                rules.Add(new Rule("CUSTOM", "(?i)" + Regex.Escape(word.Trim())));

        // Parts that are already encrypted must never be detected again.
        var alreadyEncrypted = TextEncryptor.TokenPattern.Matches(text)
            .Select(m => new Finding("TOKEN", m.Index, m.Length, m.Value)).ToList();

        // Arabic-Indic digits (٠١٢٣...) become 0123... in a copy of the text that is used for searching.
        // One character is replaced by one character, so every position stays the same.
        string search = new(text.Select(c => char.IsDigit(c) ? (char)('0' + (int)char.GetNumericValue(c)) : c).ToArray());

        var results = new List<Finding>();
        foreach (var rule in rules)
        {
            foreach (Match match in Regex.Matches(search, rule.Pattern))
            {
                Group part = match.Groups["v"].Success ? match.Groups["v"] : match;
                var finding = new Finding(rule.Type, part.Index, part.Length, text.Substring(part.Index, part.Length));

                bool valid = rule.IsValid == null || rule.IsValid(part.Value);
                bool free = !results.Any(finding.Overlaps) && !alreadyEncrypted.Any(finding.Overlaps);
                if (valid && free)
                    results.Add(finding);
            }
        }
        return results.OrderBy(f => f.Start).ToList();
    }

    /// <summary>Luhn checksum used by all payment cards (Visa, MasterCard, ...).</summary>
    public static bool IsValidCard(string number)
    {
        int[] digits = number.Where(char.IsDigit).Select(c => (int)char.GetNumericValue(c)).ToArray();
        if (digits.Length < 13 || digits.Length > 19) return false;

        int sum = 0;
        for (int i = 0; i < digits.Length; i++)
        {
            int d = digits[digits.Length - 1 - i];   // walk from the right
            if (i % 2 == 1)                          // every second digit is doubled
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
        }
        return sum % 10 == 0;
    }

    /// <summary>IBAN check (ISO 13616): move first 4 chars to the end, letters -> numbers, result mod 97 must be 1.</summary>
    public static bool IsValidIban(string iban)
    {
        iban = iban.Replace(" ", "");
        if (iban.Length < 15 || iban.Length > 34) return false;

        string rearranged = iban[4..] + iban[..4];
        int remainder = 0;
        foreach (char c in rearranged)
        {
            int value = char.IsDigit(c) ? c - '0' : c - 'A' + 10;   // A=10, B=11, ... Z=35
            remainder = (remainder * (value < 10 ? 10 : 100) + value) % 97;
        }
        return remainder == 1;
    }
}
