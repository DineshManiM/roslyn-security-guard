using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests.Taint
{
    [TestClass]
    public class PathTraversalAnalyzerTest : DiagnosticVerifier
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
            return new[] { MetadataReference.CreateFromFile(typeof(File).Assembly.Location) };
        }


        [TestMethod]
        public void PathTraversalFound1()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.ReadAllText(input);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void PathTraversalFound2()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.OpenRead(input);
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void PathTraversalFound3()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.WriteAllText(input,""ouput.."");
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }

        [TestMethod]
        public void FalsePositive1()
        {
            var test = @"
using System.IO;

class PathTraversal
{
    public static void Run(string input)
    {
        return File.OpenRead(""C:/static/fsociety.dat"");
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void PathTraversalFound1Ex()
        {
            var test = @"
Imports System.IO
Class PathTraversal
    Public Function Run(input As String)
        Return File.ReadAllText(input)
    End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyVbDiagnostic(test, expected);
        }

        [TestMethod]
        public void PathTraversalFound2Ex()
        {
            var test = @"
Imports System.IO
Class PathTraversal
    Public Function Run(input As String)
        Return File.OpenRead(input)
    End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyVbDiagnostic(test, expected);
        }


        [TestMethod]
        public void PathTraversalFound3Ex()
        {
            var test = @"
Imports System.IO
Class PathTraversal
    Public Function Run(input As String)
        File.WriteAllText(input, ""ouput.."")
    End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0018",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyVbDiagnostic(test, expected);
        }

        [TestMethod]
        public void FalsePositive1Ex()
        {
            var test = @"
Imports System.IO
Class PathTraversal
    Public Function Run(input As String)
        Return File.OpenRead(""C:/static/fsociety.dat"")
    End Function
End Class
";
            VerifyVbDiagnostic(test);
        }

        #endregion
    }
}
