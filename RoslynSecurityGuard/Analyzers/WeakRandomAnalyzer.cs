using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WeakRandomAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0005");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);


        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNodeEx, Microsoft.CodeAnalysis.VisualBasic.SyntaxKind.InvocationExpression, Microsoft.CodeAnalysis.VisualBasic.SyntaxKind.ObjectCreationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            InvocationExpressionSyntax node = ctx.Node as InvocationExpressionSyntax;
            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                //System.Random.Next()
                if (AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "Next") ||
                    AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "NextBytes") ||
                    AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "NextDouble"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }

        private static void VisitSyntaxNodeEx(SyntaxNodeAnalysisContext ctx)
        {
            Microsoft.CodeAnalysis.VisualBasic.Syntax.InvocationExpressionSyntax node = ctx.Node as Microsoft.CodeAnalysis.VisualBasic.Syntax.InvocationExpressionSyntax;
            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                //System.Random.Next()
                if (AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "Next") ||
                    AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "NextBytes") ||
                    AnalyzerUtil.SymbolMatch(symbol, type: "Random", name: "NextDouble"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
