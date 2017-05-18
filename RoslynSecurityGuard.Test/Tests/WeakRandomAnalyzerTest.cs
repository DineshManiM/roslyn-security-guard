using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System;
using System.Collections.Generic;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class WeakRandomAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new WeakRandomAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new WeakRandomAnalyzer() };
        }

        [TestMethod]
        public void RandomFalsePositive()
        {
            var code = @"using System;
using System.Security.Cryptography;

class WeakRandom
{
    static String generateSecureToken()
    {

        RandomNumberGenerator rnd = RandomNumberGenerator.Create();

        byte[] buffer = new byte[16];
        rnd.GetBytes(buffer);
        return BitConverter.ToString(buffer);
    }
}
";
            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void RandomVulnerable1()
        {
            var code = @"
using System;
using System.Security.Cryptography;

class WeakRandom
{
    static String generateWeakToken()
    {
        Random rnd = new Random();
        return rnd.Next().ToString(); //Vulnerable
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0005",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation(10, -1);

            VerifyCSharpDiagnostic(code, expected);
        }


        #region VB.Net Test cases

        [TestMethod]
        public void RandomFalsePositiveEx()
        {
            var code = @"Imports System
Imports System.Security.Cryptography

Class WeakRandom
    Function generateSecureToken() As String

        Dim rnd As RandomNumberGenerator = RandomNumberGenerator.Create()

        Dim buffer() As Byte = New Byte(16) {}
        rnd.GetBytes(buffer)
        Return BitConverter.ToString(buffer)
    End Function
End Class
";
            VerifyVbDiagnostic(code);
        }

        [TestMethod]
        public void RandomVulnerable1Ex()
        {
            var code = @"Imports System
Imports System.Security.Cryptography;

Class WeakRandom
    Function generateWeakToken() As String
        Dim rnd As Random = New Random()
        Return rnd.Next().ToString() 'Vulnerable
    End Function
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SG0005",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation("Test0.vb",7, -1);

            VerifyVbDiagnostic(code, expected);
        }

        #endregion
    }
}
