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
    public class CsrfTokenAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new [] { new CsrfTokenAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new CsrfTokenAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(ValidateAntiForgeryTokenAttribute).Assembly.Location) };
        }
        
        [TestMethod]
        public void CsrfDetectMissingToken()
        {
            var test = @"
                using System;
                using System.Diagnostics;
                using System.Web.Mvc;

                namespace VulnerableApp
                {
                    public class TestController
                    {
                        [HttpPost]
                        //[ValidateAntiForgeryToken]
                        public ActionResult ControllerMethod(string input) {

                            return null;
                        }
                    }
                }
                ";
            var expected = new DiagnosticResult
            {
                Id = "SG0016",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void CsrfValidateAntiForgeryTokenPresent()
        {
            var test = @"
                using System;
                using System.Diagnostics;
                using System.Web.Mvc;

                namespace VulnerableApp
                {
                    public class TestController
                    {
                        [HttpPost]
                        [ValidateAntiForgeryToken]
                        public ActionResult ControllerMethod(string input) {

                            return null;
                        }
                    }
                }
                ";

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void CsrfValidateAntiForgeryTokenPresentWithInlinedAttributes()
        {
            var test = @"
                using System;
                using System.Diagnostics;
                using System.Web.Mvc;

                namespace VulnerableApp
                {
                    public class TestController
                    {
                        [HttpPost, ValidateAntiForgeryToken]
                        public ActionResult ControllerMethod(string input) {
                            return null;
                        }
                    }
                }
                ";

            VerifyCSharpDiagnostic(test);
        }

        
        #region VB.Net Test cases
        [TestMethod]
        public void CsrfDetectMissingTokenEx()
        {
            var test = @"
Imports System.Diagnostics
Imports System.Web.Mvc

Namespace VulnerableApp
	Public Class TestController
		<HttpPost()> _
		Public Function ControllerMethod(input As String) As ActionResult

			Return Nothing
		End Function
	End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0016",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test, expected);
        }

        [TestMethod]
        public void CsrfValidateAntiForgeryTokenPresentEx()
        {
            var test = @"
Imports System.Diagnostics
Imports System.Web.Mvc

Namespace VulnerableApp
	Public Class TestController
		<HttpPost()> _
        <ValidateAntiForgeryToken()> _
		Public Function ControllerMethod(input As String) As ActionResult

			Return Nothing
		End Function
	End Class
End Namespace
";

            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void CsrfValidateAntiForgeryTokenPresentWithInlinedAttributesEx()
        {
            var test = @"
Imports System.Diagnostics
Imports System.Web.Mvc

Namespace VulnerableApp
	Public Class TestController
		<HttpPost(),ValidateAntiForgeryToken()> _
		Public Function ControllerMethod(input As String) As ActionResult

			Return Nothing
		End Function
	End Class
End Namespace
";

            VerifyVbDiagnostic(test);
        }

        #endregion
    }
}
