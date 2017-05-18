using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class WeakHashingAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new WeakHashingAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new WeakHashingAnalyzer() };
        }

        [TestMethod]
        public void WeakHashingFalsePositive()
        {
            var test = @"
using System;
using System.Text;
using System.Security.Cryptography;

class Sha256OK
{
    static String generateSecureHashing()
    {
        string source = ""Hello World!"";
        SHA256 sha256 = SHA256.Create();
        byte[] data = sha256.ComputeHash(Encoding.UTF8.GetBytes(source));

        StringBuilder sBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString(""x2""));
        }

        // Return the hexadecimal string. 
        return sBuilder.ToString();
    }
}";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void WeakHashingVulnerableMd5()
        {
            var test = @"
using System;
using System.Text;
using System.Security.Cryptography;

class WeakHashing
{

    static String generateWeakHashingMD5()
    {
        string source = ""Hello World!"";
        MD5 md5 = MD5.Create();
        byte[] data = md5.ComputeHash(Encoding.UTF8.GetBytes(source));

        StringBuilder sBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString(""x2""));
        }

        // Return the hexadecimal string. 
        return sBuilder.ToString();
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0006",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void WeakHashingVulnerableSha1()
        {
            var test = @"
using System;
using System.Text;
using System.Security.Cryptography;

class WeakHashing
{

    static String generateWeakHashingSHA1()
    {
        string source = ""Hello World!"";
        SHA1 sha1 = SHA1.Create();
        byte[] data = sha1.ComputeHash(Encoding.UTF8.GetBytes(source));

        StringBuilder sBuilder = new StringBuilder();
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString(""x2""));
        }

        // Return the hexadecimal string. 
        return sBuilder.ToString();
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0006",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void WeakHashingFalsePositiveEx()
        {
            var test = @"
Imports System
Imports System.Text
Imports System.Security.Cryptography

Class Sha256OK
    Private Shared Function generateSecureHashing() As String
        Dim source As String = ""Hello World!""
        Dim sha256__1 As SHA256 = SHA256.Create()
        Dim data As Byte() = sha256__1.ComputeHash(Encoding.UTF8.GetBytes(source))

        Dim sBuilder As New StringBuilder()
        For i As Integer = 0 To data.Length - 1
            sBuilder.Append(data(i).ToString(""x2""))
        Next

        ' Return the hexadecimal string. 
        Return sBuilder.ToString()
    End Function
End Class";
            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void WeakHashingVulnerableMd5Ex()
        {
            var test = @"
Imports System
Imports System.Text
Imports System.Security.Cryptography

Class WeakHashing

	Private Shared Function generateWeakHashingMD5() As String
		Dim source As String = ""Hello World!""

        Dim md5__1 As MD5 = MD5.Create()

        Dim data As Byte() = md5__1.ComputeHash(Encoding.UTF8.GetBytes(source))


        Dim sBuilder As New StringBuilder()

        For i As Integer = 0 To data.Length - 1

            sBuilder.Append(data(i).ToString(""x2""))

        Next


        ' Return the hexadecimal string. 

        Return sBuilder.ToString()

    End Function
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SG0006",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test, expected);
        }

        [TestMethod]
        public void WeakHashingVulnerableSha1Ex()
        {
            var test = @"
Imports System
Imports System.Text
Imports System.Security.Cryptography

Class WeakHashing

	Private Shared Function generateWeakHashingSHA1() As String
		Dim source As String = ""Hello World!""

        Dim sha1__1 As SHA1 = SHA1.Create()

        Dim data As Byte() = sha1__1.ComputeHash(Encoding.UTF8.GetBytes(source))


        Dim sBuilder As New StringBuilder()

        For i As Integer = 0 To data.Length - 1

            sBuilder.Append(data(i).ToString(""x2""))

        Next


        ' Return the hexadecimal string. 

        Return sBuilder.ToString()

    End Function
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SG0006",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test, expected);
        }

        #endregion
    }
}
