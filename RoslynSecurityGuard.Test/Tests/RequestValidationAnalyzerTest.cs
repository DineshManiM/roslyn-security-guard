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
    public class RequestValidationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new RequestValidationAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new RequestValidationAnalyzer() };
        }

        [TestMethod]
        public void DetectAnnotationValidateInput()
        {
            var test = @"
using System;
using System.Diagnostics;

namespace VulnerableApp
{
    public class TestController
    {
        [HttpPost]
        [ValidateInput(false)]
        public ActionResult ControllerMethod(string input) {

            return null;
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0017",
                Severity = DiagnosticSeverity.Warning
            };
            VerifyCSharpDiagnostic(test,expected);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void DetectAnnotationValidateInputEx()
        {
            var test = @"
Imports System.Diagnostics
Imports System.Web.Mvc

Namespace VulnerableApp
	Public Class TestController
		<HttpPost()> _
        <ValidateInput(false)> _
		Public Function ControllerMethod(input As String) As ActionResult

			Return Nothing
		End Function
	End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SG0017",
                Severity = DiagnosticSeverity.Warning
            };
            VerifyVbDiagnostic(test, expected);
        }

        #endregion

        [ValidateInput(false)]
        public ActionResult ControllerMethod(string input)
        {
            return null;
        }
    }
}
