using System.Collections.Generic;
using System.Xml;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class XxeAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new [] { new XxeAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new XxeAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(XmlNode).Assembly.Location) };
        }

        [TestMethod]
        public void XxeFalsePositive1()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void XxeFalsePositive2()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.ProhibitDtd = true;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            VerifyCSharpDiagnostic(code);
        }


        [TestMethod]
        public void XxeFalsePositive3()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void XxeFalsePositive4()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Ignore;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            VerifyCSharpDiagnostic(code);
        }

        [TestMethod]
        public void XxeVulnerable1()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.ProhibitDtd = false;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";

            var expected = new[] {
                new DiagnosticResult {Id = "SG0007",Severity = DiagnosticSeverity.Warning}};

            VerifyCSharpDiagnostic(code, expected);
        }

        [TestMethod]
        public void XxeVulnerable2()
        {
            var code = @"
using System;
using System.Xml;

class Xxe
{
    public static void parseUpload(string inputXml)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse;
        XmlReader reader = XmlReader.Create(inputXml, settings);

    }
}";
            var expected = new[] {
                new DiagnosticResult {Id = "SG0007",Severity = DiagnosticSeverity.Warning}};

            VerifyCSharpDiagnostic(code, expected);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void XxeFalsePositive1Ex()
        {
            var code = @"
Imports System
Imports System.Xml

Class Xxe
    Public Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class";

            VerifyVbDiagnostic(code);
        }

        [TestMethod]
        public void XxeFalsePositive2Ex()
        {
            var code = @"
Imports System
Imports System.Xml

Class Xxe
    Public Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
        settings.ProhibitDtd = True
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class";

            VerifyVbDiagnostic(code);
        }


        [TestMethod]
        public void XxeFalsePositive3Ex()
        {
            var code = @"
Imports System
Imports System.Xml

Class Xxe
    Public Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
        settings.DtdProcessing = DtdProcessing.Prohibit
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class";

            VerifyVbDiagnostic(code);
        }

        [TestMethod]
        public void XxeFalsePositive4Ex()
        {
            var code = @"
Imports System
Imports System.Xml

Class Xxe
    Public Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
        settings.DtdProcessing = DtdProcessing.Ignore
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class";

            VerifyVbDiagnostic(code);
        }

        [TestMethod]
        public void XxeVulnerable1Ex()
        {
            var code = @"
Imports System
Imports System.Xml

Class Xxe
    Public Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
        settings.ProhibitDtd = False
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class";

            var expected = new[] {
                new DiagnosticResult {Id = "SG0007",Severity = DiagnosticSeverity.Warning}};

            VerifyVbDiagnostic(code, expected);
        }

        [TestMethod]
        public void XxeVulnerable2Ex()
        {
            var code = @"
Imports System
Imports System.Xml

Class Xxe
    Public Sub parseUpload(inputXml As String)
        Dim settings As New XmlReaderSettings()
        settings.DtdProcessing = DtdProcessing.Parse
        Dim reader As XmlReader = XmlReader.Create(inputXml, settings)
    End Sub
End Class";
            var expected = new[] {
                new DiagnosticResult {Id = "SG0007",Severity = DiagnosticSeverity.Warning}};

            VerifyVbDiagnostic(code, expected);
        }

        #endregion
    }
}
