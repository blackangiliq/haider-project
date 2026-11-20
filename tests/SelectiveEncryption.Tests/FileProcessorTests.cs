using SelectiveEncryption;

public class FileProcessorTests
{
    static string SamplesFolder()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(dir.FullName, "HaiderProject.sln"))) dir = dir.Parent!;
        return Path.Combine(dir.FullName, "samples");
    }

    [Fact]
    public async Task Whole_sample_folder_is_encrypted_then_restored()
    {
        string root = Path.Combine(Path.GetTempPath(), "selenc-tests-" + Guid.NewGuid());
        string encrypted = Path.Combine(root, "encrypted"), decrypted = Path.Combine(root, "decrypted");

        var encResults = await FileProcessor.ProcessFolderAsync(SamplesFolder(), encrypted, "Test#123", encrypt: true);
        var decResults = await FileProcessor.ProcessFolderAsync(encrypted, decrypted, "Test#123", encrypt: false);

        Assert.All(encResults, r => Assert.Equal("OK", r.Status));
        Assert.All(decResults, r => Assert.Equal("OK", r.Status));
        Assert.True(File.Exists(Path.Combine(encrypted, "report.csv")));

        foreach (string name in new[] { "personal_notes.txt", "employees.csv", "accounts.json" })
        {
            string original = File.ReadAllText(Path.Combine(SamplesFolder(), name));
            Assert.NotEqual(original, File.ReadAllText(Path.Combine(encrypted, name)));
            Assert.Equal(original, File.ReadAllText(Path.Combine(decrypted, name)));
        }
        Directory.Delete(root, recursive: true);
    }

    [Theory]
    [InlineData(@"C:\a\notes.txt", true, @"C:\a\notes.enc.txt")]
    [InlineData(@"C:\a\notes.enc.txt", false, @"C:\a\notes.dec.txt")]
    [InlineData(@"C:\a\photo.jpg", true, @"C:\a\photo.enc.png")]
    public void Output_names(string input, bool encrypt, string expected) =>
        Assert.Equal(expected, FileProcessor.OutputPath(input, encrypt));
}
