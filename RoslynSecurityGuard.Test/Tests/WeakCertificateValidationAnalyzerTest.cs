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
    public class WeakCertificateValidationAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new WeakCertificateValidationAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new WeakCertificateValidationAnalyzer() };
        }

        [TestMethod]
        public void WeakCertFalsePositive()
        {
            var code = @"
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Text;

class OkCert {
    public void DoGetRequest1()
    {
        string url = ""https://hack.me/"";

        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);

        HttpWebResponse response = (HttpWebResponse)request.GetResponse();

        String responseBody = StreamToString(response.GetResponseStream());
        Console.WriteLine(responseBody);
        Console.Read();
    }
}
";
            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void WeakCertVulnerable1()
        {
            var code = @"using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Text;

class weakCert {
    public void DoGetRequest1()
    {
/**/    ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;

        string url = ""https://hack.me/"";

        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);

        HttpWebResponse response = (HttpWebResponse)request.GetResponse();

        String responseBody = StreamToString(response.GetResponseStream());
        Console.WriteLine(responseBody);
        Console.Read();
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0004",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation(10,-1);

            VerifyCSharpDiagnostic(code, expected);
        }

        [TestMethod]
        public void WeakCertVulnerable2()
        {
            var code = @"using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Text;

class weakCert {
    public void DoGetRequest1()
    {
/**/    ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;

        string url = ""https://hack.me/"";

        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);

        HttpWebResponse response = (HttpWebResponse)request.GetResponse();

        String responseBody = StreamToString(response.GetResponseStream());
        Console.WriteLine(responseBody);
        Console.Read();
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0004",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation(10, -1);

            VerifyCSharpDiagnostic(code, expected);
        }


        #region VB.Net Test cases

        [TestMethod]
        public void WeakCertFalsePositiveEx()
        {
            var code = @"
Imports System.IO
Imports System.Net
Imports System.Net.Security
Imports System.Text

Class OkCert
    Public Sub DoGetRequest1()
        Dim url As String = ""https://hack.me/""

        Dim request As HttpWebRequest = DirectCast(WebRequest.Create(url), HttpWebRequest)

        Dim response As HttpWebResponse = DirectCast(request.GetResponse(), HttpWebResponse)

        Dim responseBody As Stream = (response.GetResponseStream())
        Console.WriteLine(responseBody)
        Console.Read()
    End Sub
End Class
";
            VerifyVbDiagnostic(code);
        }

        [TestMethod]
        public void WeakCertVulnerable1Ex()
        {
            var code = @"Imports System.IO
Imports System.Net
Imports System.Net.Security
Imports System.Text

Class weakCert
    Public Sub DoGetRequest1()

        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => True

        Dim url As String = ""https://hack.me/""

            Dim request As HttpWebRequest = DirectCast(WebRequest.Create(url), HttpWebRequest)

        Dim response As HttpWebResponse = DirectCast(request.GetResponse(), HttpWebResponse)

        Dim responseBody As Stream = (response.GetResponseStream())
        Console.WriteLine(responseBody)
        Console.Read()
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SG0004",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation("Test0.vb",9, -1);

            VerifyVbDiagnostic(code, expected);
        }

        [TestMethod]
        public void WeakCertVulnerable2Ex()
        {
            var code = @"Imports System.IO
Imports System.Net
Imports System.Net.Security
Imports System.Text

Class weakCert
	Public Sub DoGetRequest1()
		'
        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => True

		Dim url As String = String.Empty

		Dim request As HttpWebRequest = DirectCast(WebRequest.Create(url), HttpWebRequest)

		Dim response As HttpWebResponse = DirectCast(request.GetResponse(), HttpWebResponse)

		Dim responseBody As [String] = StreamToString(response.GetResponseStream())
		Console.WriteLine(responseBody)
		Console.Read()
	End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SG0004",
                Severity = DiagnosticSeverity.Warning,
            }.WithLocation("Test0.vb",9, -1);

            VerifyVbDiagnostic(code, expected);
        }

        #endregion
    }
}
