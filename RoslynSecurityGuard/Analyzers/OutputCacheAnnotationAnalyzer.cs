﻿using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;
using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class OutputCacheAnnotationAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SG0019";
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitClass, SyntaxKind.ClassDeclaration);
            context.RegisterSyntaxNodeAction(VisitClassEx, Microsoft.CodeAnalysis.VisualBasic.SyntaxKind.ClassBlock);
        }

        private void VisitClass(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as ClassDeclarationSyntax;

            if (node == null)
            { //Not the expected node type
                return;
            }

            var classHasAuthAnnotation = false;
            var classHasCacheAnnotation = false;

            AnalyzerUtil.ForEachAnnotation(node.AttributeLists, 
                delegate (string Name, AttributeSyntax att) {
                    if (Name == "Authorize") {
                        classHasAuthAnnotation = true;
                    }
                    else if (Name == "OutputCache")
                    {
                        classHasCacheAnnotation = true;
                    }
                }
            );

            foreach (MemberDeclarationSyntax member in node.Members) {
                var method = member as MethodDeclarationSyntax;
                if (method == null) continue;

                var methodHasAuthAnnotation = false;
                var methodHasCacheAnnotation = false;
                AnalyzerUtil.ForEachAnnotation(method.AttributeLists,
                    delegate (string Name, AttributeSyntax att) {
                        if (Name == "Authorize")
                        {
                            methodHasAuthAnnotation = true;
                        }
                        else if (Name == "OutputCache")
                        {
                            methodHasCacheAnnotation = true;
                        }
                    }
                );

                bool hasAuth = classHasAuthAnnotation || methodHasAuthAnnotation;
                bool hasCache = classHasCacheAnnotation || methodHasCacheAnnotation;

                if (hasAuth && hasCache) {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, method.GetLocation()));
                }
            }

        }

        private void VisitClassEx(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as Microsoft.CodeAnalysis.VisualBasic.Syntax.ClassBlockSyntax;

            if (node == null)
            { //Not the expected node type
                return;
            }

            var classHasAuthAnnotation = false;
            var classHasCacheAnnotation = false;

            AnalyzerUtil.ForEachAnnotationEx(node.ClassStatement.AttributeLists,
                delegate (string Name, Microsoft.CodeAnalysis.VisualBasic.Syntax.AttributeSyntax att) {
                    if (Name == "Authorize")
                    {
                        classHasAuthAnnotation = true;
                    }
                    else if (Name == "OutputCache")
                    {
                        classHasCacheAnnotation = true;
                    }
                }
            );

            foreach (Microsoft.CodeAnalysis.VisualBasic.Syntax.StatementSyntax member in node.Members)
            {
                var method = member as Microsoft.CodeAnalysis.VisualBasic.Syntax.MethodBlockSyntax;
                if (method == null) continue;

                var methodHasAuthAnnotation = false;
                var methodHasCacheAnnotation = false;
                AnalyzerUtil.ForEachAnnotationEx(method.BlockStatement.AttributeLists,
                    delegate (string Name, Microsoft.CodeAnalysis.VisualBasic.Syntax.AttributeSyntax att)
                    {
                        if (Name == "Authorize")
                        {
                            methodHasAuthAnnotation = true;
                        }
                        else if (Name == "OutputCache")
                        {
                            methodHasCacheAnnotation = true;
                        }
                    }
                );

                bool hasAuth = classHasAuthAnnotation || methodHasAuthAnnotation;
                bool hasCache = classHasCacheAnnotation || methodHasCacheAnnotation;

                if (hasAuth && hasCache)
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, method.GetLocation()));
                }
            }

        }
    }
}
