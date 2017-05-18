using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.Data.SqlClient;
using TestHelper;

namespace RoslynSecurityGuard.Tests
{
    [TestClass]
    public class TaintAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzer() };
        }
   
        protected override IEnumerable<DiagnosticAnalyzer> GetVbDiagnosticAnalyzers()
        {
            return new List<DiagnosticAnalyzer> { new TaintAnalyzer() };
        }


        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(System.Data.SqlClient.SqlCommand).Assembly.Location) };
        }

        [TestMethod]
        public void VariableTransferSimple()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run()
        {
            string username = ""Hello Friend.."";
            var variable1 = username;
            var variable2 = variable1;

            new SqlCommand(variable2);
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void VariableConcatenation()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run()
        {
            string username = ""Shall we play a game?"";

            new SqlCommand(""SELECT* FROM users WHERE username = '"" + username + ""' LIMIT 1"");
        }
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void VariableTransferWithConcatenation()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run()
        {
            string username = ""This is all safe"";
            var variable1 = username;
            var variable2 = variable1;

            new SqlCommand(""SELECT* FROM users WHERE username = '"" + variable2 + ""' LIMIT 1"");
        }
    }
}
";

            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void VariableTransferUnsafe()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string username = input;
            var variable1 = username;
            var variable2 = variable1;

            new SqlCommand(variable2);
        }
    }
}
";
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }


        [TestMethod]
        public void VariableConcatenationUnsafe()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            new SqlCommand(""SELECT* FROM users WHERE username = '"" + input + ""' LIMIT 1"");
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }



        [TestMethod]
        public void VariableOverride() {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            {
                string username = ""ignore_me"";
            }
            {
                string username = input;
                new SqlCommand(""SELECT* FROM users WHERE username = '"" + username + ""' LIMIT 1"");
            }
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }



        [TestMethod]
        public void VariableReuse()
        {
            var test = @"
using System.Data.SqlClient;

namespace sample
{
    class SqlConstant
    {
        public static void Run(string input)
        {
            string query = ""SELECT * FROM [User] WHERE user_id = 1"";
            SqlCommand cmd1 = new SqlCommand(query);

            query = input;
            SqlCommand cmd2 = new SqlCommand(query);
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyCSharpDiagnostic(test, expected);
        }

        #region VB.Net Test cases

        [TestMethod]
        public void VariableTransferSimpleEx()
        {
            var test = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Sub Run()
            Dim username As String = ""Hello Friend..""
            Dim variable1 = username
            Dim variable2 = variable1

            Dim cmd As SqlCommand = New SqlCommand(variable2)
        End Sub
    End Class
End Namespace
";
            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void VariableConcatenationEx()
        {
            var test = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Sub Run()
            Dim username As String = ""Hello Friend..""
            Dim cmd As SqlCommand = New SqlCommand(""SELECT* FROM users WHERE username = '"" + username + ""' LIMIT 1"")
        End Sub
    End Class
End Namespace
";
            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void VariableTransferWithConcatenationEx()
        {
            var test = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Sub Run()
            Dim username As String = ""Hello Friend..""
            Dim variable1 As String = username
            Dim variable2 As String = variable1
            Dim cmd As SqlCommand = New SqlCommand(""SELECT* FROM users WHERE username = '"" + variable2 + ""' LIMIT 1"")
        End Sub
    End Class
End Namespace
";

            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void VariableTransferUnsafeEx()
        {
            var test = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Sub Run(input As String)
            Dim username As String = input
            Dim variable1 As String = username
            Dim variable2 As String = variable1
            Dim cmd As SqlCommand = New SqlCommand(variable2)
        End Sub
    End Class
End Namespace
";
            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyVbDiagnostic(test, expected);
        }


        [TestMethod]
        public void VariableConcatenationUnsafeEx()
        {
            var test = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Sub Run(input As String)
            Dim cmd As SqlCommand = New SqlCommand(""SELECT * FROM users WHERE username = '"" + input + ""' LIMIT 1"")
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyVbDiagnostic(test, expected);
        }


        [TestMethod]
        public void VariableReuseEx()
        {
            var test = @"
Imports System.Data.SqlClient

Namespace sample
    Class SqlConstant
        Public Sub Run(input As String)
            
            Dim query As String = ""SELECT * FROM [User] WHERE user_id = 1""
            Dim cmd1 As SqlCommand = New SqlCommand(query)
            
            query = input
            Dim cmd2 As SqlCommand = New SqlCommand(query)
        End Sub
    End Class
End Namespace
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };
            VerifyVbDiagnostic(test, expected);
        }



        #endregion

        /*
                public static void Run(string input)
                {
                    string query = "SELECT* FROM[User] WHERE user_id = 1";
                    new SqlCommand(query);

                    query = input;
                    new SqlCommand(query);
                }
        */
    }
}
