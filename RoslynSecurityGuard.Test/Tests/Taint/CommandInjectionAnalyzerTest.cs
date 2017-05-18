using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Diagnostics;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{

    [TestClass]
    public class CommandInjectionAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        //No diagnostics expected to show up
        [TestMethod]
        public void CommandInjectionFalsePositive()
        {
            var test = @"
using System;
using System.Diagnostics;

namespace VulnerableApp
{
    class ProcessExec
    {
        static void TestCommandInject(string input)
        {
                Process.Start(""dir"");
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }



        [TestMethod]
        public void CommandInjectionFalsePositive_Filename()
        {
            var test = @"
using System;
using System.Diagnostics;

namespace VulnerableApp
{
    class ProcessExec
    {
        static void TestCommandInject(string input)
        {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = ""1234"";
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test);
        }
        
        [TestMethod]
        public void CommandInjectionVulnerable1()
        {
            var test = @"
using System;
using System.Diagnostics;

namespace VulnerableApp
{
    class ProcessExec
    {
        static void TestCommandInject(string input)
        {
            Process.Start(input);
        }
    }
}
        ";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void CommandInjectionVulnerable2()
        {
            var test = @"
using System;
using System.Diagnostics;

namespace VulnerableApp
{
    class ProcessExec
    {
        static void TestCommandInject(string input)
        {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = input;
            //Process.Start(p);
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void CommandInjectionFalsePositiveEx()
        {
            var test = @"
Imports System
Imports System.Diagnostics
 
Namespace VulnerableApp
    Class ProcessExec
        Sub TestCommandInject(ByVal input As String)
                Process.Start(""dir"")
        End Sub
    End Class
End Namespace
";
            VerifyVbDiagnostic(test);
        }



        [TestMethod]
        public void CommandInjectionFalsePositive_FilenameEx()
        {
            var test = @"
Imports System
Imports System.Diagnostics
 
Namespace VulnerableApp
    Class ProcessExec
        Sub TestCommandInject(ByVal input As String)
            Dim p As ProcessStartInfo =  New ProcessStartInfo() 
            p.FileName = ""1234""
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void CommandInjectionVulnerable1Ex()
        {
            var test = @"
Imports System
Imports System.Diagnostics
 
Namespace VulnerableApp
    Class ProcessExec
        Sub TestCommandInject(ByVal input As String)
            Process.Start(input)
        End Sub
    End Class
End Namespace
        ";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test, expected);
        }


        [TestMethod]
        public void CommandInjectionVulnerable2Ex()
        {
            var test = @"
Imports System
Imports System.Diagnostics
 
Namespace VulnerableApp
    Class ProcessExec
        Sub TestCommandInject(ByVal input As String)
            Dim p As ProcessStartInfo =  New ProcessStartInfo() 
            p.FileName = input
            'Process.Start(p);
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SG0001",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyVbDiagnostic(test, expected);
        }

        #endregion


        private void sandbox(string input) {
            ProcessStartInfo p = new ProcessStartInfo();
            p.FileName = input;
            p.Arguments = input;
            Process.Start(p);
        }
    }
}