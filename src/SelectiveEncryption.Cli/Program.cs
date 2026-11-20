using System.Text;
using SelectiveEncryption;

// Command line version of the project.
//   selenc scan    <file>                     show the sensitive items (no changes)
//   selenc ocr     <image>                    show what Windows OCR reads in an image
//   selenc encrypt <file> [-o out] [-p pass] [-w "word1,word2"]
//   selenc decrypt <file> [-o out] [-p pass]
//   selenc encrypt-folder <input folder> <output folder> [-p pass] [-w ...]
//   selenc decrypt-folder <input folder> <output folder> [-p pass]

Console.OutputEncoding = Encoding.UTF8;   // so Arabic text is printed correctly

if (args.Length < 2)
{
    Console.WriteLine("""
        Selective Encryption for Protecting Sensitive Information in Personal Digital Files

        Usage:
          selenc scan    <file>
          selenc ocr     <image>
          selenc encrypt <file> [-o output] [-p password] [-w "word1,word2"]
          selenc decrypt <file> [-o output] [-p password]
          selenc encrypt-folder <input folder> <output folder> [-p password] [-w ...]
          selenc decrypt-folder <input folder> <output folder> [-p password]

        Supported: .txt .csv .json .log .md  and images .png .jpg .jpeg .bmp
        """);
    return 1;
}

string command = args[0];
string path = args[1];
string[]? words = Option("-w")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

try
{
    switch (command)
    {
        case "scan":
            if (FileProcessor.IsImage(path))
                foreach (var r in await ImageEncryptor.AnalyzeAsync(File.ReadAllBytes(path), words))
                    Console.WriteLine($"{r.Type,-12} {r.Text}   at x={r.Box.X} y={r.Box.Y} w={r.Box.Width} h={r.Box.Height}");
            else
                foreach (var f in TextEncryptor.Analyze(File.ReadAllText(path), Path.GetExtension(path), words))
                    Console.WriteLine($"{f.Type,-12} {f.Value}   at position {f.Start}");
            break;

        case "ocr":
            foreach (var line in await WindowsOcr.ReadAsync(File.ReadAllBytes(path)))
                Console.WriteLine($"[{line.Language}] {line.Text}");
            break;

        case "encrypt":
        {
            string output = Option("-o") ?? FileProcessor.OutputPath(path, encrypt: true);
            int count = await FileProcessor.EncryptFileAsync(path, output, Password(), words);
            Console.WriteLine($"Encrypted {count} sensitive item(s) -> {output}");
            break;
        }

        case "decrypt":
        {
            string output = Option("-o") ?? FileProcessor.OutputPath(path, encrypt: false);
            int count = FileProcessor.DecryptFile(path, output, Password());
            Console.WriteLine($"Restored {count} item(s) -> {output}");
            break;
        }

        case "encrypt-folder":
        case "decrypt-folder":
        {
            if (args.Length < 3) throw new ArgumentException("Please give an input folder and an output folder.");
            var results = await FileProcessor.ProcessFolderAsync(path, args[2], Password(), command == "encrypt-folder", words);
            foreach (var r in results)
                Console.WriteLine($"{r.Status,-8} {r.Items,3} item(s) {r.Milliseconds,6} ms   {r.File}");
            Console.WriteLine($"Done: {results.Count(r => r.Status == "OK")} of {results.Count} file(s). Report: {Path.Combine(args[2], "report.csv")}");
            break;
        }

        default:
            Console.WriteLine($"Unknown command: {command}");
            return 1;
    }
    return 0;
}
catch (Exception ex)
{
    Console.WriteLine("Error: " + ex.Message);
    return 2;
}

// Value after an option, e.g. Option("-o") for "-o out.txt"
string? Option(string name)
{
    int i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

// Use -p if given, otherwise ask without showing the typed characters.
string Password()
{
    string? password = Option("-p");
    if (password != null) return password;

    Console.Write("Password: ");
    var typed = new StringBuilder();
    ConsoleKeyInfo key;
    while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
    {
        if (key.Key == ConsoleKey.Backspace) { if (typed.Length > 0) typed.Length--; }
        else typed.Append(key.KeyChar);
    }
    Console.WriteLine();
    return typed.ToString();
}
