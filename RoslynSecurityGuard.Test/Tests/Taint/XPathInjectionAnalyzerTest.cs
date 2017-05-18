using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TestHelper;
using System.Collections.Generic;
using System.Xml;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class XPathInjectionAnalyzerTest : DiagnosticVerifier
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
            return new[] { MetadataReference.CreateFromFile(typeof(XmlNode).Assembly.Location) };
        }

        //No diagnostics expected to show up
        [TestMethod]
        public void XPathInjectionFalsePositive()
        {
            var test = @"
using System.Xml;

class XPathInjectionTP
{

    public void vulnerableCases(string input) {
        XmlDocument doc = new XmlDocument();
        doc.Load(""/secret_config.xml"");

        doc.SelectNodes(""/Config/Devices/Device[id='1337']"");
        doc.SelectSingleNode(""/Config/Devices/Device[type='2600']"");
    }
}";
            VerifyCSharpDiagnostic(test);
        }
        
        [TestMethod]
        public void XPathInjectionVulnerable1()
        {
            var test = @"
using System.Xml;

class XPathInjectionTP
{

    public void vulnerableCases(string input) {
        XmlDocument doc = new XmlDocument();
        doc.Load(""/secret_config.xml"");

        doc.SelectNodes(""/Config/Devices/Device[id='"" + input + ""']"");
        doc.SelectSingleNode(""/Config/Devices/Device[type='"" + input + ""']"");
    }
}";
            //Two occurrences
            var expected = new[] {
                new DiagnosticResult {Id = "SG0003",Severity = DiagnosticSeverity.Warning},
                new DiagnosticResult { Id = "SG0003", Severity = DiagnosticSeverity.Warning} };

            VerifyCSharpDiagnostic(test, expected);
        }

        //Make sure MemberAccessExpressionSyntax are covered
        [TestMethod]
        public void XPathInjectionVulnerable2()
        {
            var test = @"
using System.Xml;

class XPathInjectionTP
{

    public void vulnerableCases(string input) {
        XmlDocument doc = new XmlDocument();
        doc.Load(""/secret_config.xml"");

        doc.SelectNodes(""/Config/Devices/Device[id='"" + input + ""']"").Count;
        doc.SelectSingleNode(""/Config/Devices/Device[type='"" + input + ""']"").Value;
    }
}";
            //Two occurrences
            var expected = new[] {
                new DiagnosticResult {Id = "SG0003",Severity = DiagnosticSeverity.Warning},
                new DiagnosticResult { Id = "SG0003", Severity = DiagnosticSeverity.Warning} };

            VerifyCSharpDiagnostic(test, expected);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void XPathInjectionFalsePositiveEx()
        {
            var test = @"
Imports System.Xml

Class XPathInjectionTP

    Public Sub vulnerableCases(input As String)
        Dim doc As New XmlDocument()
        doc.Load("" / secret_config.xml"")

        doc.SelectNodes(""/Config/Devices/Device[id='1337']"")
        doc.SelectSingleNode(""/Config/Devices/Device[type='2600']"")
    End Sub
End Class";
            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void XPathInjectionVulnerable1Ex()
        {
            var test = @"
Imports System.Xml

Class XPathInjectionTP

    Public Sub vulnerableCases(input As String)
        Dim doc As New XmlDocument()
        doc.Load("" / secret_config.xml"")

        doc.SelectNodes("" / Config / Devices / Device[id='"" & input + ""']"")
        doc.SelectSingleNode("" / Config / Devices / Device[type='"" & input + ""']"")
    End Sub
End Class";
            //Two occurrences
            var expected = new[] {
                new DiagnosticResult {Id = "SG0003",Severity = DiagnosticSeverity.Warning},
                new DiagnosticResult { Id = "SG0003", Severity = DiagnosticSeverity.Warning} };

            VerifyVbDiagnostic(test, expected);
        }

        //Make sure MemberAccessExpressionSyntax are covered
        [TestMethod]
        public void XPathInjectionVulnerable2Ex()
        {
            var test = @"
Imports System.Xml

Class XPathInjectionTP

    Public Sub vulnerableCases(input As String)
        Dim doc As New XmlDocument()
        doc.Load("" / secret_config.xml"")

        Dim cnt As Integer = doc.SelectNodes("" / Config / Devices / Device[id='"" & input + ""']"").Count
        Dim val As String = doc.SelectSingleNode("" / Config / Devices / Device[type='"" & input + ""']"").Value
    End Sub
End Class";
            //Two occurrences
            var expected = new[] {
                new DiagnosticResult {Id = "SG0003",Severity = DiagnosticSeverity.Warning},
                new DiagnosticResult { Id = "SG0003", Severity = DiagnosticSeverity.Warning} };

            VerifyVbDiagnostic(test, expected);
        }

        #endregion
    }
}
