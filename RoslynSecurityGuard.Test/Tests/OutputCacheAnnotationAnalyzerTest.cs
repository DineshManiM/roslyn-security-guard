using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;

using System.Collections.Generic;

using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class OutputCacheAnnotationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new OutputCacheAnnotationAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new OutputCacheAnnotationAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(OutputCacheAttribute).Assembly.Location) };
        }

        [TestMethod]
        public void DetectAnnotation1()
        {
            var test = @"
using System;
using System.Web.Mvc;

[Authorize]
public class HomeController : Controller
{
    [OutputCache]        
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0019",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void DetectAnnotation2()
        {
            var test = @"
using System;
using System.Web.Mvc;

public class HomeController : Controller
{
    [Authorize]
    [OutputCache]        
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0019",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void FalsePositive1()
        {
            var test = @"
using System;
using System.Web.Mvc;

public class HomeController : Controller
{
    [OutputCache]        
    public ActionResult Index()
    {
        return View();
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0019",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test);
        }


        #region VB.Net Test cases

        [TestMethod]
        public void DetectAnnotation1Ex()
        {
            var test = @"
Imports System.Diagnostics
Imports System.Web.Mvc

<Authorize()>
Public Class NControlDataRow
    Implements IComparable
       <OutputCache()> _
    Public Function Nettolista(form As FormCollection) As ActionResult
        Return View()
    End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0019",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test, expected);
        }

        [TestMethod]
        public void DetectAnnotation2Ex()
        {
            var test = @"
Imports System.Diagnostics
Imports System.Web.Mvc

Public Class NControlDataRow
    Implements IComparable
       <Authorize()> _
       <OutputCache()> _
    Public Function Nettolista(form As FormCollection) As ActionResult
        Return View()
    End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0019",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test, expected);
        }

        [TestMethod]
        public void FalsePositive1Ex()
        {
            var test = @"
Imports System.Diagnostics
Imports System.Web.Mvc

Public Class NControlDataRow
    Implements IComparable
       <OutputCache()> _
    Public Function Nettolista(form As FormCollection) As ActionResult
        Return View()
    End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0019",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test);
        }

        #endregion

        [Authorize]
        [OutputCache]
        public ActionResult ControllerMethod()
        {

            return null;
        }
    }
}
