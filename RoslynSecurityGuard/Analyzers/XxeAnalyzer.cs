﻿using System.Collections.Immutable;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class XxeAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0007");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.SimpleAssignmentExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNodeEx, Microsoft.CodeAnalysis.VisualBasic.SyntaxKind.SimpleAssignmentStatement);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var assignment = ctx.Node as AssignmentExpressionSyntax;
            var memberAccess = assignment?.Left as MemberAccessExpressionSyntax;
            if (memberAccess == null) return;

            var symbolMemberAccess = ctx.SemanticModel.GetSymbolInfo(memberAccess).Symbol;
            if (AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "XmlReaderSettings", name: "ProhibitDtd"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(assignment.Right);
                if (constant.HasValue && constant.Value.ToString() == "False")
                {
                    var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
            else if (AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "XmlReaderSettings", name: "DtdProcessing"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(assignment.Right);
                if (constant.HasValue && constant.Value.ToString() == "2")
                {
                    var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }

        private static void VisitSyntaxNodeEx(SyntaxNodeAnalysisContext ctx)
        {
            var assignment = ctx.Node as Microsoft.CodeAnalysis.VisualBasic.Syntax.AssignmentStatementSyntax;
            var memberAccess = assignment?.Left as Microsoft.CodeAnalysis.VisualBasic.Syntax.MemberAccessExpressionSyntax;
            if (memberAccess == null) return;

            var symbolMemberAccess = ctx.SemanticModel.GetSymbolInfo(memberAccess).Symbol;
            if (AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "XmlReaderSettings", name: "ProhibitDtd"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(assignment.Right);
                if (constant.HasValue && constant.Value.ToString() == "False")
                {
                    var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
            else if (AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "XmlReaderSettings", name: "DtdProcessing"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(assignment.Right);
                if (constant.HasValue && constant.Value.ToString() == "2")
                {
                    var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
