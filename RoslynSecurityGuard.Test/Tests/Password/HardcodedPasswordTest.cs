using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;

using System.Collections.Generic;
using System.Security.Cryptography;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class HardcodedPasswordTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            //Making sure cryptography assembly is loaded
            return new[] { MetadataReference.CreateFromFile(typeof(PasswordDeriveBytes).Assembly.Location) };
        }

        [TestMethod]
        public void HardCodePasswordDerivedBytes()
        {

            var test = @"
using System.Collections.Generic;
using System.Security.Cryptography;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestHardcodedValue()
        {
            var test = new PasswordDeriveBytes(""hardcode"", new byte[] { 0, 1, 2, 3 });
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0015",
                Severity = DiagnosticSeverity.Warning
            };
            VerifyCSharpDiagnostic(test, expected );
        }


        [TestMethod]
        public void HardCodePasswordDerivedBytesFalsePositive()
        {

            var test = @"
using System.Collections.Generic;
using System.Security.Cryptography;

namespace VulnerableApp
{
    class HardCodedPassword
    {
        static void TestHardcodedValue(string input)
        {
            var test = new PasswordDeriveBytes(input, new byte[] { 0, 1, 2, 3 });
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void HardCodePasswordDerivedBytesEx()
        {

            var test = @"
Imports System.Collections.Generic
Imports System.Security.Cryptography

Namespace VulnerableApp
    Class HardCodedPassword
        Private Shared Sub TestHardcodedValue()
            Dim test = New PasswordDeriveBytes(""hardcode"", New Byte() {0, 1, 2, 3})
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SG0015",
                Severity = DiagnosticSeverity.Warning
            };
            VerifyVbDiagnostic(test, expected);
        }


        [TestMethod]
        public void HardCodePasswordDerivedBytesFalsePositiveEx()
        {

            var test = @"
Imports System.Collections.Generic
Imports System.Security.Cryptography

Namespace VulnerableApp
	Class HardCodedPassword
		Private Shared Sub TestHardcodedValue(input As String)
			Dim test = New PasswordDeriveBytes(input, New Byte() {0, 1, 2, 3})
		End Sub
	End Class
End Namespace
";
            VerifyVbDiagnostic(test);
        }

        #endregion

        private void sandbox()
        {
            var test = new PasswordDeriveBytes("test", new byte[] { 0, 1, 2, 3 });
        }
    }
}
