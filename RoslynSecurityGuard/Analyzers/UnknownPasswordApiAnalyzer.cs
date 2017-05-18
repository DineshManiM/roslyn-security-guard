using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Taint;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class UnknownPasswordApiAnalyzer : DiagnosticAnalyzer, CSharpTaintAnalyzerExtension, VbTaintAnalyzerExtension
    {

        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0015");
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        private List<string> PasswordKeywords = new List<string> {"password", "motdepasse", "heslo", "adgangskode", "wachtwoord", "salasana", "passwort", "passord",
            "senha","geslo", "clave", "losenord", "clave", "parola", "secretkey", "pwd"};

        public override void Initialize(AnalysisContext context)
        {
            TaintAnalyzer.RegisterExtension(this, this);
        }


        public void VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            if (behavior == null && //Unknown API
                    (symbol != null && IsPasswordField(symbol)) &&
                    variableRightState.taint == VariableTaint.CONSTANT //Only constant
                    )
            {
                var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
        }


        public void VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state)
        {

        }

        public void VisitBeginMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
        {

        }
        
        public void VisitStatement(StatementSyntax node, ExecutionState state)
        {

        }

        public void VisitEndMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
        {

        }

        private bool IsPasswordField(ISymbol symbol)
        {
            return PasswordKeywords.Contains(symbol.MetadataName.ToLower());
            //return symbol.MetadataName.ToLower().Contains("password");
        }

        public void VisitAssignment(Microsoft.CodeAnalysis.VisualBasic.Syntax.AssignmentStatementSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
        {
            if (behavior == null && //Unknown API
                    (symbol != null && IsPasswordField(symbol)) &&
                    variableRightState.taint == VariableTaint.CONSTANT //Only constant
                    )
            {
                var diagnostic = Diagnostic.Create(Rule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
        }

        public void VisitEndMethodDeclaration(Microsoft.CodeAnalysis.VisualBasic.Syntax.MethodBlockSyntax node, ExecutionState state)
        {

        }

        public void VisitBeginMethodDeclaration(Microsoft.CodeAnalysis.VisualBasic.Syntax.MethodBlockSyntax node, ExecutionState state)
        {

        }

        public void VisitStatement(Microsoft.CodeAnalysis.VisualBasic.Syntax.StatementSyntax node, ExecutionState state)
        {

        }
        public void VisitInvocationAndCreation(Microsoft.CodeAnalysis.VisualBasic.Syntax.ExpressionSyntax node, Microsoft.CodeAnalysis.VisualBasic.Syntax.ArgumentListSyntax argList, ExecutionState state)
        {

        }
    }
}
