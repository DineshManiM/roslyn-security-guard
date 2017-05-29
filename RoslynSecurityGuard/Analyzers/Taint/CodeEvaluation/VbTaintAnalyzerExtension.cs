using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public interface VbTaintAnalyzerExtension
    {

        void VisitStatement(StatementSyntax node, ExecutionState state);

        void VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state);

        void VisitAssignment(AssignmentStatementSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState);



        void VisitBeginMethodDeclaration(MethodBlockSyntax node, ExecutionState state);

        void VisitEndMethodDeclaration(MethodBlockSyntax node, ExecutionState state);


    }
}
