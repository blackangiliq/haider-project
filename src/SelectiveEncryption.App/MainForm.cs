using System.Text.RegularExpressions;

namespace SelectiveEncryption.App;

/// <summary>
/// The main window, with three tabs: text files, images (Windows OCR) and whole folders.
/// The window only shows data and reacts to buttons. All the real work is done by the
/// SelectiveEncryption.Core library (Detector, TextEncryptor, ImageEncryptor, FileProcessor).
/// </summary>
public class MainForm : Form
{
    // ---------- shared controls ----------
    readonly TextBox passwordBox = new() { Name = "passwordBox", UseSystemPasswordChar = true, Width = 200 };
    readonly TextBox wordsBox = new() { Name = "wordsBox", Width = 320, PlaceholderText = "optional, e.g. Ahmed, Project X" };
    readonly Label status = new() { Name = "status", Dock = DockStyle.Bottom, Height = 32, Padding = new Padding(8, 0, 0, 0), TextAlign = ContentAlignment.MiddleLeft };

    // ---------- tab 1: text files ----------
    readonly RichTextBox textView = new() { Dock = DockStyle.Fill, ReadOnly = true, BackColor = Color.White, Font = new Font("Segoe UI", 11), WordWrap = false };
    readonly ListView textList = NewList(true, ("Type", 120), ("Value", 270));
    string? textPath;              // the open file
    string text = "";              // its current content (new lines as \n)
    bool windowsLineEndings;       // true if the file used \r\n
    List<Finding> findings = [];

    // ---------- tab 2: images ----------
    readonly PictureBox picture = new() { Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.FromArgb(243, 244, 246) };
    readonly ListView imageList = NewList(true, ("Type", 120), ("Text read by OCR", 270));
    string? imagePath;
    byte[]? imageFile;             // the current image file (original or encrypted)
    List<ImageRegion> regions = [];

    // ---------- tab 3: folders ----------
    readonly TextBox inputFolderBox = new() { Name = "inputFolderBox", Width = 560 };
    readonly TextBox outputFolderBox = new() { Name = "outputFolderBox", Width = 560 };
    readonly ListView folderList = NewList(false, ("File", 380), ("Status", 240), ("Items", 70), ("Time (ms)", 90));

    public MainForm()
    {
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96, 96);
        Text = "Selective Encryption for Protecting Sensitive Information in Personal Digital Files";
        Font = new Font("Segoe UI", 10);
        Size = new Size(1280, 780);
        StartPosition = FormStartPosition.CenterScreen;

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 46, Padding = new Padding(6, 8, 6, 0) };
        top.Controls.AddRange([Caption("Password:"), passwordBox, Caption("    Extra words to hide (comma separated):"), wordsBox]);

        var tabs = new TabControl { Name = "tabs", Dock = DockStyle.Fill, Padding = new Point(14, 6) };
        tabs.TabPages.AddRange([TextTab(), ImageTab(), FolderTab()]);

        Controls.Add(tabs);      // the "Fill" control is added first, then the edges
        Controls.Add(top);
        Controls.Add(status);
        ShowStatus("Open a file, check the detected items, type a password, then press Encrypt.");
    }

    // =====================================================================
    // Tab 1: text files
    // =====================================================================
    TabPage TextTab()
    {
        var page = new TabPage("1. Text files (TXT / CSV / JSON)");
        var bar = Toolbar(
            NewButton("Open file…", (_, _) =>
            {
                using var dialog = new OpenFileDialog { Filter = "Text files|*.txt;*.csv;*.json;*.log;*.md|All files|*.*" };
                if (dialog.ShowDialog() == DialogResult.OK) Try(() => OpenTextFile(dialog.FileName));
            }),
            NewButton("Encrypt checked items", (_, _) => Try(EncryptText)),
            NewButton("Decrypt", (_, _) => Try(DecryptText)),
            NewButton("Save as…", (_, _) => Try(SaveText)));

        textList.Dock = DockStyle.Right;
        textList.Width = 420;
        textView.HandleCreated += (_, _) => UseUnicodeBidi(textView);
        page.Controls.AddRange([textView, textList, bar]);
        return page;
    }

    // By default the RichTextBox carries the direction of an Arabic line into the next lines,
    // so "+964 781 234 5678" in an English line after Arabic lines is drawn as "+5678 234 781 964".
    // This option makes it use the standard Unicode bidi algorithm instead (display only).
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern IntPtr SendMessage(IntPtr window, int message, IntPtr wParam, ref BidiOptions lParam);
    struct BidiOptions { public int Size; public ushort Mask, Effects; }

    static void UseUnicodeBidi(RichTextBox box)
    {
        const int EM_SETBIDIOPTIONS = 0x0400 + 200, BOE_UNICODEBIDI = 0x0080;
        var options = new BidiOptions { Size = 8, Mask = BOE_UNICODEBIDI, Effects = BOE_UNICODEBIDI };
        SendMessage(box.Handle, EM_SETBIDIOPTIONS, IntPtr.Zero, ref options);
    }

    public void OpenTextFile(string path)
    {
        string content = File.ReadAllText(path);
        textPath = path;
        windowsLineEndings = content.Contains("\r\n");
        text = content.Replace("\r\n", "\n");   // RichTextBox counts a new line as one character
        findings = TextEncryptor.Analyze(text, Path.GetExtension(path), CustomWords());
        ShowText();
        ShowStatus($"{Path.GetFileName(path)}: {findings.Count} sensitive item(s) found. Untick anything you want to leave visible.");
    }

    public void EncryptText()
    {
        var chosen = textList.CheckedItems.Cast<ListViewItem>().Select(item => (Finding)item.Tag!).ToList();
        if (chosen.Count == 0) throw new InvalidOperationException("Nothing is checked to encrypt.");

        text = TextEncryptor.Encrypt(text, chosen, Password());
        findings = [];
        ShowText();
        ShowStatus($"{chosen.Count} item(s) encrypted with AES-256-GCM. The rest of the file is unchanged. Use 'Save as…' to keep the result.");
    }

    public void DecryptText()
    {
        int count = TextEncryptor.TokenPattern.Matches(text).Count;
        if (count == 0) throw new InvalidOperationException("This text has no encrypted items.");

        text = TextEncryptor.Decrypt(text, Password());
        findings = TextEncryptor.Analyze(text, Path.GetExtension(textPath)!, CustomWords());
        ShowText();
        ShowStatus($"{count} item(s) decrypted. The original text is back.");
    }

    void SaveText()
    {
        if (textPath == null) throw new InvalidOperationException("Open a file first.");
        bool encrypted = TextEncryptor.TokenPattern.IsMatch(text);
        using var dialog = new SaveFileDialog
        {
            InitialDirectory = Path.GetDirectoryName(textPath),
            FileName = Path.GetFileName(FileProcessor.OutputPath(textPath, encrypted)),
        };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(dialog.FileName, windowsLineEndings ? text.Replace("\n", "\r\n") : text);
        ShowStatus("Saved: " + dialog.FileName);
    }

    void ShowText()
    {
        textView.Text = text;
        foreach (var f in findings)
            Highlight(f.Start, f.Length, ColorOf(f.Type));
        foreach (Match token in TextEncryptor.TokenPattern.Matches(text))
            Highlight(token.Index, token.Length, Color.FromArgb(226, 232, 240));
        textView.Select(0, 0);

        textList.Items.Clear();
        foreach (var f in findings)
            textList.Items.Add(new ListViewItem([f.Type, f.Value]) { Checked = true, Tag = f, BackColor = ColorOf(f.Type) });
    }

    void Highlight(int start, int length, Color color)
    {
        textView.Select(start, length);
        textView.SelectionBackColor = color;
    }

    // =====================================================================
    // Tab 2: images (Windows OCR)
    // =====================================================================
    TabPage ImageTab()
    {
        var page = new TabPage("2. Images (Windows OCR)");
        var bar = Toolbar(
            NewButton("Open image…", async (_, _) =>
            {
                using var dialog = new OpenFileDialog { Filter = "Images|*.png;*.jpg;*.jpeg;*.bmp" };
                if (dialog.ShowDialog() == DialogResult.OK) await TryAsync(() => OpenImageAsync(dialog.FileName));
            }),
            NewButton("Encrypt checked regions", (_, _) => Try(EncryptImage)),
            NewButton("Decrypt", (_, _) => Try(DecryptImage)),
            NewButton("Save as…", (_, _) => Try(SaveImage)));

        imageList.Dock = DockStyle.Right;
        imageList.Width = 420;
        imageList.ItemChecked += (_, _) => picture.Invalidate();
        picture.Paint += DrawRegions;
        page.Controls.AddRange([picture, imageList, bar]);
        return page;
    }

    public async Task OpenImageAsync(string path)
    {
        imagePath = path;
        imageFile = File.ReadAllBytes(path);
        bool encrypted = ImageEncryptor.IsEncrypted(imageFile);
        regions = [];
        ShowImage();
        if (encrypted)
        {
            ShowStatus("This image is encrypted. Type the password and press Decrypt.");
            return;
        }
        ShowStatus("Reading the image with Windows OCR…");
        regions = await ImageEncryptor.AnalyzeAsync(imageFile, CustomWords());
        ShowImage();
        ShowStatus($"{Path.GetFileName(path)}: Windows OCR found {regions.Count} sensitive region(s) (red boxes).");
    }

    public void EncryptImage()
    {
        var chosen = imageList.CheckedItems.Cast<ListViewItem>().Select(item => (ImageRegion)item.Tag!).ToList();
        if (chosen.Count == 0) throw new InvalidOperationException("Nothing is checked to encrypt.");

        imageFile = ImageEncryptor.Encrypt(imageFile!, chosen, Password());
        regions = chosen;
        ShowImage();
        ShowStatus($"{chosen.Count} region(s) encrypted: their pixels are now AES-256-GCM ciphertext. Use 'Save as…' (PNG).");
    }

    public void DecryptImage()
    {
        if (imageFile == null) throw new InvalidOperationException("Open an image first.");
        imageFile = ImageEncryptor.Decrypt(imageFile, Password(), out int count);
        ShowImage();
        ShowStatus($"{count} region(s) decrypted. The original pixels are back.");
    }

    void SaveImage()
    {
        if (imagePath == null || imageFile == null) throw new InvalidOperationException("Open an image first.");
        using var dialog = new SaveFileDialog
        {
            Filter = "PNG image|*.png",
            InitialDirectory = Path.GetDirectoryName(imagePath),
            FileName = Path.GetFileName(FileProcessor.OutputPath(imagePath, ImageEncryptor.IsEncrypted(imageFile))),
        };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        File.WriteAllBytes(dialog.FileName, imageFile);
        ShowStatus("Saved: " + dialog.FileName);
    }

    void ShowImage()
    {
        picture.Image?.Dispose();
        picture.Image = Image.FromStream(new MemoryStream(imageFile!));
        imageList.Items.Clear();
        foreach (var r in regions)
            imageList.Items.Add(new ListViewItem([r.Type, r.Text]) { Checked = true, Tag = r, BackColor = ColorOf(r.Type) });
    }

    /// <summary>Draws a red box around every checked region (image pixels -> zoomed screen pixels).</summary>
    void DrawRegions(object? sender, PaintEventArgs e)
    {
        if (picture.Image == null) return;
        float scale = Math.Min((float)picture.Width / picture.Image.Width, (float)picture.Height / picture.Image.Height);
        float offsetX = (picture.Width - picture.Image.Width * scale) / 2;
        float offsetY = (picture.Height - picture.Image.Height * scale) / 2;

        using var pen = new Pen(Color.Red, 2);
        foreach (ListViewItem item in imageList.CheckedItems)
        {
            Rectangle box = ((ImageRegion)item.Tag!).Box;
            e.Graphics.DrawRectangle(pen, offsetX + box.X * scale, offsetY + box.Y * scale, box.Width * scale, box.Height * scale);
        }
    }

    // =====================================================================
    // Tab 3: a whole folder
    // =====================================================================
    TabPage FolderTab()
    {
        var page = new TabPage("3. Whole folder");
        var grid = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, Padding = new Padding(8) };
        grid.Controls.Add(Caption("Input folder:"), 0, 0);
        grid.Controls.Add(inputFolderBox, 1, 0);
        grid.Controls.Add(BrowseButton(inputFolderBox), 2, 0);
        grid.Controls.Add(Caption("Output folder:"), 0, 1);
        grid.Controls.Add(outputFolderBox, 1, 1);
        grid.Controls.Add(BrowseButton(outputFolderBox), 2, 1);

        var buttons = new FlowLayoutPanel { AutoSize = true };
        buttons.Controls.AddRange(
        [
            NewButton("Encrypt all files", async (_, _) => await TryAsync(() => ProcessFolderAsync(encrypt: true))),
            NewButton("Decrypt all files", async (_, _) => await TryAsync(() => ProcessFolderAsync(encrypt: false))),
        ]);
        grid.Controls.Add(buttons, 1, 2);

        page.Controls.AddRange([folderList, grid]);
        return page;
    }

    public async Task ProcessFolderAsync(bool encrypt)
    {
        string input = inputFolderBox.Text, output = outputFolderBox.Text, password = Password();
        string[] words = CustomWords();
        if (!Directory.Exists(input)) throw new DirectoryNotFoundException("Choose an existing input folder.");
        if (output.Length == 0) throw new InvalidOperationException("Choose an output folder.");

        folderList.Items.Clear();
        ShowStatus(encrypt ? "Encrypting the folder…" : "Decrypting the folder…");

        // Progress<T> brings every result back to the window thread, so the list can be updated.
        var progress = new Progress<FileResult>(r =>
            folderList.Items.Add(new ListViewItem([r.File, r.Status, r.Items.ToString(), r.Milliseconds.ToString()])));
        var results = await Task.Run(() => FileProcessor.ProcessFolderAsync(input, output, password, encrypt, words, progress));

        ShowStatus($"Done: {results.Count(r => r.Status == "OK")} of {results.Count} file(s). Report saved to {Path.Combine(output, "report.csv")}");
    }

    // =====================================================================
    // Small helpers
    // =====================================================================
    string Password() =>
        passwordBox.Text.Length > 0 ? passwordBox.Text : throw new InvalidOperationException("Please type a password first.");

    string[] CustomWords() =>
        wordsBox.Text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    void ShowStatus(string message, bool error = false)
    {
        status.Text = message;
        status.ForeColor = error ? Color.Firebrick : Color.FromArgb(30, 41, 59);
    }

    // Any error is shown in the status bar instead of closing the program.
    void Try(Action action)
    {
        try { action(); }
        catch (Exception ex) { ShowStatus("Error: " + ex.Message, error: true); }
    }

    async Task TryAsync(Func<Task> action)
    {
        try { await action(); }
        catch (Exception ex) { ShowStatus("Error: " + ex.Message, error: true); }
    }

    static Color ColorOf(string type) => type switch
    {
        "EMAIL" => Color.FromArgb(191, 219, 254),
        "PHONE" => Color.FromArgb(187, 247, 208),
        "CARD" => Color.FromArgb(254, 215, 170),
        "IBAN" => Color.FromArgb(254, 240, 138),
        "PASSWORD" => Color.FromArgb(254, 202, 202),
        "NATIONAL_ID" => Color.FromArgb(233, 213, 255),
        "IP" => Color.FromArgb(165, 243, 252),
        _ => Color.FromArgb(251, 207, 232),   // CUSTOM and CSV columns
    };

    static Label Caption(string text) => new() { Text = text, AutoSize = true, Margin = new Padding(3, 7, 3, 0) };

    static Button NewButton(string text, EventHandler onClick)
    {
        var button = new Button { Text = text, AutoSize = true, Height = 34, Padding = new Padding(8, 0, 8, 0) };
        button.Click += onClick;
        return button;
    }

    Button BrowseButton(TextBox target) => NewButton("Browse…", (_, _) =>
    {
        using var dialog = new FolderBrowserDialog();
        if (dialog.ShowDialog() == DialogResult.OK) target.Text = dialog.SelectedPath;
    });

    static FlowLayoutPanel Toolbar(params Button[] buttons)
    {
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 48, Padding = new Padding(4, 6, 4, 0) };
        bar.Controls.AddRange(buttons);
        return bar;
    }

    static ListView NewList(bool checkBoxes, params (string Title, int Width)[] columns)
    {
        var list = new ListView { Dock = DockStyle.Fill, View = View.Details, CheckBoxes = checkBoxes, FullRowSelect = true, GridLines = true };
        foreach (var (title, width) in columns) list.Columns.Add(title, width);
        return list;
    }
}
