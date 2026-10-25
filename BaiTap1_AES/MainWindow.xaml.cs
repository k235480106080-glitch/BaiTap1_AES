using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using Microsoft.Win32;

namespace BaiTap1_AES
{
    public partial class MainWindow : Window
    {
        private byte[] currentKey;
        private byte[] currentIV;
        private const int BufferSize = 1024 * 1024; // Buffer 1MB tối ưu file lớn

        public MainWindow()
        {
            InitializeComponent();
            LogInfo("Hệ thống mã hóa AES-256 (CBC + PKCS7) đã sẵn sàng.");
            LogInfo("Sinh viên: Trần Hoàng Xuân Vũ | Mã SV: K235480106080");
            LogInfo("Hãy bấm [1. Khởi Tạo Khóa Mới] hoặc [3. Nạp Khóa Từ File] để bắt đầu.\n");
        }

        #region Console Logging Helpers
        private void LogInfo(string message) => AppendLog($"[i] {message}\n", Color.FromRgb(56, 189, 248));      // Blue Cyan
        private void LogHeader(string title) => AppendLog($"\n>>> {title} <<<\n", Color.FromRgb(251, 191, 36)); // Amber Yellow
        private void LogSuccess(string message) => AppendLog($"[+] {message}\n", Color.FromRgb(52, 211, 153));    // Emerald Green
        private void LogError(string message) => AppendLog($"[-] ERROR: {message}\n", Color.FromRgb(248, 113, 113)); // Bright Red

        private void AppendLog(string text, Color color)
        {
            Dispatcher.Invoke(() =>
            {
                TextRange tr = new TextRange(rtbLog.Document.ContentEnd, rtbLog.Document.ContentEnd)
                {
                    Text = text
                };
                tr.ApplyPropertyValue(TextElement.ForegroundProperty, new SolidColorBrush(color));
                rtbLog.ScrollToEnd();
            });
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e)
        {
            rtbLog.Document.Blocks.Clear();
        }
        #endregion

        #region 1. Sinh khóa & IV
        private void BtnGenKey_Click(object sender, RoutedEventArgs e)
        {
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateKey();
                aes.GenerateIV();

                currentKey = aes.Key;
                currentIV = aes.IV;
            }

            LogHeader("1. KHỞI TẠO KHÓA AES-256 MỚI THÀNH CÔNG");
            LogSuccess($"Key (Base64 - 256 bits): {Convert.ToBase64String(currentKey)}");
            LogSuccess($"IV  (Base64 - 128 bits): {Convert.ToBase64String(currentIV)}");
        }
        #endregion

        #region 2. Lưu khóa ra File
        private void BtnSaveKey_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyAndIV()) return;

            SaveFileDialog sfd = new SaveFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt",
                FileName = "aes_key.txt"
            };

            if (sfd.ShowDialog() == true)
            {
                string keyData = $"KEY:{Convert.ToBase64String(currentKey)}\nIV:{Convert.ToBase64String(currentIV)}";
                File.WriteAllText(sfd.FileName, keyData);
                LogSuccess($"[2] Đã xuất khóa thành công ra file: {sfd.FileName}");
            }
        }
        #endregion

        #region 3. Import khóa từ File
        private void BtnImportKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog { Filter = "Text Files (*.txt)|*.txt" };

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    string[] lines = File.ReadAllLines(ofd.FileName);
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("KEY:"))
                            currentKey = Convert.FromBase64String(line.Substring(4).Trim());
                        else if (line.StartsWith("IV:"))
                            currentIV = Convert.FromBase64String(line.Substring(3).Trim());
                    }

                    LogHeader("3. NẠP KHÓA TỪ FILE THÀNH CÔNG");
                    LogSuccess($"Key (Base64): {Convert.ToBase64String(currentKey)}");
                    LogSuccess($"IV  (Base64): {Convert.ToBase64String(currentIV)}");
                }
                catch (Exception ex)
                {
                    LogError($"Lỗi nạp khóa: {ex.Message}");
                }
            }
        }
        #endregion

        #region 4. Mã hóa & Giải mã Văn bản
        private void BtnEncryptText_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyAndIV()) return;

            string plainText = txtInputText.Text;
            if (string.IsNullOrEmpty(plainText)) return;

            byte[] cipherBytes = EncryptStringToBytes_Aes(plainText, currentKey, currentIV);
            string base64Text = Convert.ToBase64String(cipherBytes);
            string hexText = Convert.ToHexString(cipherBytes);

            LogHeader("4a. KẾT QUẢ MÃ HÓA VĂN BẢN");
            LogInfo($"Plaintext  : {plainText}");
            LogSuccess($"Ciphertext (Base64): {base64Text}");
            LogSuccess($"Ciphertext (Hex)   : {hexText}");
        }

        private void BtnDecryptText_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyAndIV()) return;

            try
            {
                string plainText = txtInputText.Text;
                byte[] cipherBytes = EncryptStringToBytes_Aes(plainText, currentKey, currentIV);
                string decrypted = DecryptStringFromBytes_Aes(cipherBytes, currentKey, currentIV);

                LogHeader("4b. KẾT QUẢ GIẢI MÃ VĂN BẢN");
                LogSuccess($"Decrypted Text: {decrypted}");
                LogInfo($"Đối chứng gốc : {(plainText == decrypted ? "CHÍNH XÁC 100%" : "SAI LỆCH")}");
            }
            catch (Exception ex)
            {
                LogError($"Lỗi giải mã: {ex.Message}");
            }
        }

        private byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                        return ms.ToArray();
                    }
                }
            }
        }

        private string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Key;
                aes.IV = IV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
        #endregion

        #region 5. Mã hóa / Giải mã File & Benchmark File Lớn
        private async void BtnEncryptFile_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyAndIV()) return;

            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                string inputFile = ofd.FileName;
                string outputFile = inputFile + ".enc";

                LogHeader("5a. MÃ HÓA FILE TỰ CHỌN");
                await Task.Run(() => ProcessFileStream(inputFile, outputFile, isEncrypt: true));
            }
        }

        private async void BtnDecryptFile_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyAndIV()) return;

            OpenFileDialog ofd = new OpenFileDialog { Filter = "Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*" };
            if (ofd.ShowDialog() == true)
            {
                string inputFile = ofd.FileName;
                string outputFile = inputFile.EndsWith(".enc") ? inputFile.Substring(0, inputFile.Length - 4) + ".dec" : inputFile + ".dec";

                LogHeader("5b. GIẢI MÃ FILE TỰ CHỌN");
                await Task.Run(() => ProcessFileStream(inputFile, outputFile, isEncrypt: false));
            }
        }

        private async void BtnBenchmark_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyAndIV()) return;

            OpenFileDialog ofd = new OpenFileDialog { Title = "Chọn file dung lượng lớn (1GB, 2GB...) để kiểm thử" };
            if (ofd.ShowDialog() == true)
            {
                string originalFile = ofd.FileName;
                string encryptedFile = originalFile + ".enc";
                string decryptedFile = originalFile + ".dec";

                FileInfo fi = new FileInfo(originalFile);
                double sizeInMB = fi.Length / (1024.0 * 1024.0);

                LogHeader($"5c. THỬ NGHIỆM BENCHMARK FILE LỚN ({fi.Name} - {sizeInMB:N2} MB)");

                await Task.Run(() =>
                {
                    // 1. Mã hóa
                    Stopwatch swEnc = Stopwatch.StartNew();
                    ProcessFileStream(originalFile, encryptedFile, isEncrypt: true, quiet: true);
                    swEnc.Stop();
                    double encSpeed = sizeInMB / swEnc.Elapsed.TotalSeconds;
                    LogSuccess($"1. THỜI GIAN MÃ HÓA  : {swEnc.ElapsedMilliseconds} ms ({swEnc.Elapsed.TotalSeconds:F2}s)");
                    LogInfo($"   ⚡ Tốc độ trung bình: {encSpeed:F2} MB/s");

                    // 2. Giải mã
                    Stopwatch swDec = Stopwatch.StartNew();
                    ProcessFileStream(encryptedFile, decryptedFile, isEncrypt: false, quiet: true);
                    swDec.Stop();
                    double decSpeed = sizeInMB / swDec.Elapsed.TotalSeconds;
                    LogSuccess($"2. THỜI GIAN GIẢI MÃ : {swDec.ElapsedMilliseconds} ms ({swDec.Elapsed.TotalSeconds:F2}s)");
                    LogInfo($"   ⚡ Tốc độ trung bình: {decSpeed:F2} MB/s");

                    // 3. Compare Byte-by-Byte
                    Stopwatch swComp = Stopwatch.StartNew();
                    bool isIdentical = CompareFilesByteByByte(originalFile, decryptedFile);
                    swComp.Stop();

                    LogHeader("KẾT QUẢ SO SÁNH BYTE-BY-BYTE FILE GỐC VÀ FILE GIẢI MÃ");
                    LogInfo($"Thời gian kiểm tra: {swComp.ElapsedMilliseconds} ms");
                    if (isIdentical)
                        LogSuccess("✅ ĐỐI CHỨNG BYTE-BY-BYTE: CHÍNH XÁC 100% (File giải mã hoàn toàn trùng khớp file gốc)");
                    else
                        LogError("❌ ĐỐI CHỨNG BYTE-BY-BYTE: THẤT BẠI (Phát hiện dữ liệu sai lệch)");
                });
            }
        }

        private void ProcessFileStream(string inputPath, string outputPath, bool isEncrypt, bool quiet = false)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = currentKey;
                aes.IV = currentIV;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform transform = isEncrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();

                using (FileStream fsInput = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputPath, FileMode.Create, FileAccess.Write))
                using (CryptoStream cs = new CryptoStream(fsOutput, transform, CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[BufferSize];
                    int bytesRead;
                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cs.Write(buffer, 0, bytesRead);
                    }
                    cs.FlushFinalBlock();
                }
            }

            if (!quiet)
            {
                LogSuccess($"Đã {(isEncrypt ? "mã hóa" : "giải mã")} file thành công!");
                LogInfo($"Đầu ra: {outputPath}");
            }
        }

        private bool CompareFilesByteByByte(string file1, string file2)
        {
            FileInfo f1 = new FileInfo(file1);
            FileInfo f2 = new FileInfo(file2);

            if (f1.Length != f2.Length) return false;

            using (FileStream fs1 = new FileStream(file1, FileMode.Open, FileAccess.Read))
            using (FileStream fs2 = new FileStream(file2, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer1 = new byte[BufferSize];
                byte[] buffer2 = new byte[BufferSize];

                int read1, read2;
                while ((read1 = fs1.Read(buffer1, 0, buffer1.Length)) > 0)
                {
                    read2 = fs2.Read(buffer2, 0, buffer2.Length);
                    if (read1 != read2) return false;

                    for (int i = 0; i < read1; i++)
                    {
                        if (buffer1[i] != buffer2[i]) return false;
                    }
                }
            }
            return true;
        }

        private bool CheckKeyAndIV()
        {
            if (currentKey == null || currentIV == null)
            {
                LogError("Vui lòng khởi tạo hoặc nạp khóa AES trước!");
                return false;
            }
            return true;
        }
        #endregion
    }
}