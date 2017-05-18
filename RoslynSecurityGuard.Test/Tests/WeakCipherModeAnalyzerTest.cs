using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class WeakCipherModeAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new WeakCipherModeAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new WeakCipherModeAnalyzer() };
        }

        [TestMethod]
        public void WeakCipherModeECB()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


class WeakCipherMode
    {

        public static string EncryptECB(string decryptedString)
        {
            DESCryptoServiceProvider desProvider = new DESCryptoServiceProvider();
            desProvider.Mode = CipherMode.ECB;
            desProvider.Padding = PaddingMode.PKCS7;
            desProvider.Key = Encoding.ASCII.GetBytes('d66cf8');
            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(stream, desProvider.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] data = Encoding.Default.GetBytes(decryptedString);
                    cs.Write(data, 0, data.Length);
                    return Convert.ToBase64String(stream.ToArray());
                }
            }
        }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0012",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void WeakCipherModeOFB()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


class WeakCipherMode
    {

        public static string EncryptOFB(string decryptedString)
        {
            DESCryptoServiceProvider desProvider = new DESCryptoServiceProvider();
            desProvider.Mode = CipherMode.OFB;
            desProvider.Padding = PaddingMode.PKCS7;
            desProvider.Key = Encoding.ASCII.GetBytes('e5d66cf8');
            using (MemoryStream stream = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(stream, desProvider.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] data = Encoding.Default.GetBytes(decryptedString);
                    cs.Write(data, 0, data.Length);
                    return Convert.ToBase64String(stream.ToArray());
                }
            }
        }
}";
            var expected = new DiagnosticResult
            {
                Id = "SG0013",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void WeakCipherModeCBC()
        {
            var test = @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


class WeakCipherMode
    {
public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
{
    // Check arguments.
    if (plainText == null || plainText.Length <= 0)
        throw new ArgumentNullException('plainText');
    if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException('Key');
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException('IV');
            byte[] encrypted;
            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
        }
    }";
            var expected = new DiagnosticResult
            {
                Id = "SG0014",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyCSharpDiagnostic(test);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void WeakCipherModeECBEx()
        {
            var test = @"
Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Linq
Imports System.Security.Cryptography
Imports System.Text
Imports System.Threading.Tasks

Class WeakCipherMode

	Public Shared Function EncryptECB(decryptedString As String) As String
		Dim desProvider As New DESCryptoServiceProvider()
		desProvider.Mode = CipherMode.ECB
		desProvider.Padding = PaddingMode.PKCS7
		desProvider.Key = Encoding.ASCII.GetBytes(""d66cf8"")

        Using stream As New MemoryStream()

            Using cs As New CryptoStream(stream, desProvider.CreateEncryptor(), CryptoStreamMode.Write)

                Dim data As Byte() = Encoding.[Default].GetBytes(decryptedString)

                cs.Write(data, 0, data.Length)

                Return Convert.ToBase64String(stream.ToArray())

            End Using

        End Using

    End Function
End Class";
            var expected = new DiagnosticResult
            {
                Id = "SG0012",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void WeakCipherModeOFBEx()
        {
            var test = @"
Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Linq
Imports System.Security.Cryptography
Imports System.Text
Imports System.Threading.Tasks

Class WeakCipherMode

	Public Shared Function EncryptOFB(decryptedString As String) As String
		Dim desProvider As New DESCryptoServiceProvider()
		desProvider.Mode = CipherMode.OFB
		desProvider.Padding = PaddingMode.PKCS7
		desProvider.Key = Encoding.ASCII.GetBytes(""e5d66cf8"")

        Using stream As New MemoryStream()

            Using cs As New CryptoStream(stream, desProvider.CreateEncryptor(), CryptoStreamMode.Write)

                Dim data As Byte() = Encoding.[Default].GetBytes(decryptedString)

                cs.Write(data, 0, data.Length)

                Return Convert.ToBase64String(stream.ToArray())

            End Using

        End Using

    End Function
End Class";
            var expected = new DiagnosticResult
            {
                Id = "SG0013",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void WeakCipherModeCBCEx()
        {
            var test = @"
Imports System
Imports System.Collections.Generic
Imports System.IO
Imports System.Linq
Imports System.Security.Cryptography
Imports System.Text
Imports System.Threading.Tasks

Class WeakCipherMode
    Public Function EncryptStringToBytes_Aes(plainText As String, Key As Byte(), IV As Byte()) As Byte()
        ' Check arguments.
        If plainText Is Nothing OrElse plainText.Length <= 0 Then
            Throw New ArgumentNullException(""plainText"")
        End If
        If Key Is Nothing OrElse Key.Length <= 0 Then
            Throw New ArgumentNullException(""Key"")
        End If
        If IV Is Nothing OrElse IV.Length <= 0 Then
            Throw New ArgumentNullException(""IV"")
        End If
        Dim encrypted As Byte()
        ' Create an AesCryptoServiceProvider object
        ' with the specified key and IV.
        Using aesAlg As New AesCryptoServiceProvider()
            aesAlg.Key = Key
            aesAlg.IV = IV
            aesAlg.Mode = CipherMode.CBC
            aesAlg.Padding = PaddingMode.PKCS7
            ' Create a decrytor to perform the stream transform.
            Dim encryptor As ICryptoTransform = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV)

            ' Create the streams used for encryption.
            Using msEncrypt As New MemoryStream()
                Using csEncrypt As New CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)
                    Using swEncrypt As New StreamWriter(csEncrypt)

                        'Write all data to the stream.
                        swEncrypt.Write(plainText)
                    End Using
                    encrypted = msEncrypt.ToArray()
                End Using
            End Using
        End Using
    End Function
End Class";
            var expected = new DiagnosticResult
            {
                Id = "SG0014",
                Severity = DiagnosticSeverity.Warning,

            };

            VerifyVbDiagnostic(test);
        }

        #endregion
    }
}
