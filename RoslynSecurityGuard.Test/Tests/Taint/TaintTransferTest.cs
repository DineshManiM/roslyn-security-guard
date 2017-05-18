using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests.Taint
{
    [TestClass]
    public class TaintTransferTest : DiagnosticVerifier
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
        public void TransferStringFormatSafe()
        {
            var test = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run()
    {
        string tableName = ""table_name"";

        string safeQuery = String.Format(""SELECT * FROM {0}"",tableName);
        new SqlCommand(safeQuery);
    }
}
";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void TransferStringFormatUnSafe1()
        {
            var test = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string tableName = input;

        string safeQuery = String.Format(""SELECT * FROM {0}"", tableName);
        new SqlCommand(safeQuery);
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
        public void TransferStringFormatUnSafe2()
        {
            var test = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string query = input;

        string safeQuery = String.Format(query, ""test"");
        new SqlCommand(safeQuery);
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
        public void TransferStringInterpolatedSafe()
        {
            var test = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string query = input;

        string safeQuery = $""SELECT * FROM test"";
        new SqlCommand(safeQuery);
    }
}
";

            var yolo = $"123 {test.ToString()}";
            VerifyCSharpDiagnostic(test);
        }

        [TestMethod]
        public void TransferStringInterpolatedUnSafe()
        {
            var test = @"
using System;
using System.Data.SqlClient;

class SqlTransferTesting
{
    public static void Run(string input)
    {
        string query = input;

        string safeQuery = $""{query}"";
        new SqlCommand(safeQuery);
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
        public void TransferStringFormatSafeEx()
        {
            var test = @"
Imports System
Imports System.String
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run()
        Dim tableName As String = ""table_name""

        Dim safeQuery As String = Format(""SELECT * FROM {0}"", tableName)
        Dim cmd As SqlCommand = New SqlCommand(safeQuery)
    End Sub
End Class
";
            VerifyVbDiagnostic(test);
        }

        [TestMethod]
        public void TransferStringFormatUnSafe1Ex()
        {
            var test = @"
Imports System
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run(input As String)
        Dim tableName As String = input

        Dim safeQuery As String = String.Format(""SELECT * FROM {0}"", tableName)
        Dim cmd As SqlCommand = New SqlCommand(safeQuery)
    End Sub
End Class
";


            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };

            VerifyVbDiagnostic(test, expected);
        }

        [TestMethod]
        public void TransferStringFormatUnSafe2Ex()
        {
            var test = @"
Imports System
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run(input As String)
        Dim tableName As String = input

        Dim safeQuery As String = String.Format(query, ""test"")
        Dim cmd As SqlCommand = New SqlCommand(safeQuery)
    End Sub
End Class
";

            var expected = new DiagnosticResult
            {
                Id = "SG0026",
                Severity = DiagnosticSeverity.Warning,
            };

            VerifyVbDiagnostic(test, expected);
        }


        [TestMethod]
        public void TransferStringInterpolatedSafeEx()
        {
            var test = @"
Imports System
Imports System.Data.SqlClient

Class SqlTransferTesting
    Public Shared Sub Run(input As String)
        Dim tableName As String = input

        Dim safeQuery As String = $""SELECT * FROM test""
        Dim cmd As SqlCommand = New SqlCommand(safeQuery)
    End Sub
End Class
";

            var yolo = $"123 {test.ToString()}";
            VerifyVbDiagnostic(test);
        }


        #endregion
    }

}
