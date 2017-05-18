using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public class VbCodeEvaluation : BaseCodeEvaluation
    {
        public static List<VbTaintAnalyzerExtension> extensions { get; set; } = new List<VbTaintAnalyzerExtension>();

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodBlockSyntax;
            try
            {
                if (node != null)
                {
                    var state = new ExecutionState(ctx);

                    foreach (var ext in extensions)
                    {
                        ext.VisitBeginMethodDeclaration(node, state);
                    }


                    //TODO: Implement VB code evaluation
                    VisitMethodDeclaration(node, state);

                    foreach (var ext in extensions)
                    {
                        ext.VisitEndMethodDeclaration(node, state);
                    }
                }
            }
            catch (Exception e)
            {
                //Intercept the exception for logging. Otherwise, the analyzer will failed silently.
                string methodName = node.ToString();
                string errorMsg = string.Format("Unhandle exception while visiting method: {0}", e.Message);
                SGLogging.Log(errorMsg);
                throw new Exception(errorMsg, e);
            }
        }

        private VariableState VisitMethodDeclaration(MethodBlockSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax statement in node.BlockStatement.ParameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(statement.Identifier.Identifier), new VariableState(statement,VariableTaint.TAINTED));
            }

            if (node != null)
            {
                foreach (StatementSyntax statement in node.Statements)
                {
                    VisitNode(statement, state);

                    foreach (var ext in extensions)
                    {
                        ext.VisitStatement(statement, state);
                    }
                }
            }

            //The state return is irrelevant because it is not use.
            return new VariableState(node,VariableTaint.UNKNOWN);
        }

        private VariableState VisitNode(SyntaxNode node, ExecutionState state)
        {
            //Variable allocation
            if (node is LocalDeclarationStatementSyntax)
            {
                var declaration = (LocalDeclarationStatementSyntax)node;
                return VisitLocalDeclaration(declaration, state);
            }
            else if (node is VariableDeclaratorSyntax)
            {
                var declaration = (VariableDeclaratorSyntax)node;
                return VisitVariableDeclaration(declaration, state);
            }

            //Expression
            else if (node is ExpressionStatementSyntax)
            {
                var expression = (ExpressionStatementSyntax)node;
                return VisitExpressionStatement(expression, state);
            }
            else if (node is ExpressionSyntax)
            {
                var expression = (ExpressionSyntax)node;
                return VisitExpression(expression, state);
            }
            else if (node is MethodBlockSyntax)
            {
                var methodDeclaration = (MethodBlockSyntax)node;
                return VisitMethodDeclaration(methodDeclaration, state);
            }

            //Assignment
            else if (node is AssignmentStatementSyntax)
            {
                var methodDeclaration = (AssignmentStatementSyntax)node;
                return VisitAssignment(methodDeclaration, state);
            }
            else
            {
                foreach (var n in node.ChildNodes())
                {
                    VisitNode(n, state);
                }
            }

            var isBlockStatement = node is MethodBlockSyntax || node is IfStatementSyntax || node is ForEachStatementSyntax || node is ForStatementSyntax;

            if (!isBlockStatement)
            {
                SGLogging.Log("Unsupported statement " + node.GetType() + " (" + node.ToString() + ")");
            }

            return new VariableState(node,VariableTaint.UNKNOWN);
        }

        private VariableState VisitLocalDeclaration(LocalDeclarationStatementSyntax declaration, ExecutionState state)
        {
            return VisitVariableDeclaration(declaration.Declarators.First(), state);
        }

        private VariableState VisitVariableDeclaration(VariableDeclaratorSyntax declaration, ExecutionState state)
        {

            VariableState lastState = new VariableState(declaration,VariableTaint.UNKNOWN);

            var identifier = declaration.GetFirstToken();
            var initializer = declaration.Initializer;
            if (initializer is EqualsValueSyntax)
            {
                EqualsValueSyntax equalsClause = initializer;

                VariableState varState = VisitExpression(equalsClause.Value, state);
                state.AddNewValue(ResolveIdentifier(identifier), varState);
                lastState = varState;
            }

            return lastState;
        }

        private VariableState VisitExpression(ExpressionSyntax expression, ExecutionState state)
        {
            //Invocation
            if (expression is InvocationExpressionSyntax)
            {
                var invocation = (InvocationExpressionSyntax)expression;
                return VisitMethodInvocation(invocation, state);
            }
            else if (expression is ObjectCreationExpressionSyntax)
            {
                var objCreation = (ObjectCreationExpressionSyntax)expression;
                return VisitObjectCreation(objCreation, state);
            }
            else if (expression is LiteralExpressionSyntax)
            {
                return new VariableState(expression,VariableTaint.CONSTANT);
            }
            else if (expression is IdentifierNameSyntax)
            {
                var identifierName = (IdentifierNameSyntax)expression;
                return VisitIdentifierName(identifierName, state);
            }

            //Arithmetic : Addition
            else if (expression is BinaryExpressionSyntax)
            {
                var binaryExpression = (BinaryExpressionSyntax)expression;
                return VisitBinaryExpression(binaryExpression, state);
            }
            //Handles in VisitNode()
            //else if (expression is AssignmentExpressionSyntax)
            //{
            //    var assignment = (AssignmentExpressionSyntax)expression;
            //    return VisitAssignment(assignment, state);
            //}
            else if (expression is MemberAccessExpressionSyntax)
            {
                var memberAccess = (MemberAccessExpressionSyntax)expression;
                var leftExpression = memberAccess.Expression;
                var name = memberAccess.Name;
                return VisitExpression(leftExpression, state);
            }
            //else if (expression is ElementAccessExpressionSyntax)
            //{
            //    var elementAccess = (ElementAccessExpressionSyntax)expression;
            //    return VisitElementAccess(elementAccess, elementAccess.ArgumentList, state);
            //}
            else if (expression is ArrayCreationExpressionSyntax)
            {
                var arrayCreation = (ArrayCreationExpressionSyntax)expression;
                return VisitArrayCreation(arrayCreation, state);
            }
            else if (expression is TypeOfExpressionSyntax)
            {
                var typeofEx = (TypeOfExpressionSyntax)expression;
                return new VariableState(expression,VariableTaint.SAFE);
            }
            //else if (expression is BinaryConditionalExpressionSyntax)
            //{
            //    var conditional = (BinaryConditionalExpressionSyntax)expression;
            //    VisitExpression(conditional.FirstExpression, state);
            //    var finalState = new VariableState(VariableTaint.SAFE);

            //    var whenTrueState = VisitExpression(conditional.WhenTrue, state);
            //    finalState.merge(whenTrueState);
            //    var whenFalseState = VisitExpression(conditional.WhenFalse, state);
            //    finalState.merge(whenFalseState);

            //    return finalState;
            //}
            //else if (expression is CheckedExpressionSyntax)
            //{
            //    var checkedEx = (CheckedExpressionSyntax)expression;
            //    return VisitExpression(checkedEx.Expression, state);
            //}
            else if (expression is QueryExpressionSyntax)
            {
                var query = (QueryExpressionSyntax)expression;
                var body = query.GetFirstToken();
                return new VariableState(expression,VariableTaint.UNKNOWN);
            }
            else if (expression is InterpolatedStringExpressionSyntax)
            {
                var interpolatedString = (InterpolatedStringExpressionSyntax)expression;

                return VisitInterpolatedString(interpolatedString, state);
            }

            SGLogging.Log("Unsupported expression " + expression.GetType() + " (" + expression.ToString() + ")");

            //Unsupported expression
            return new VariableState(expression,VariableTaint.UNKNOWN);
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            return VisitInvocationAndCreation(node, node.ArgumentList, state);
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            return VisitInvocationAndCreation(node, node.ArgumentList, state);
        }


        private VariableState VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state)
        {

            var symbol = state.GetSymbol(node);
            MethodBehavior behavior = behaviorRepo.GetMethodBehavior(symbol);

            int i = 0;
            if (argList == null)
            {
                return new VariableState(node,VariableTaint.UNKNOWN);
            }

            var returnState = new VariableState(node,VariableTaint.SAFE);

            foreach (var argument in argList.Arguments)
            {

                var argumentState = VisitExpression(argument.GetExpression(), state);

                if (symbol != null)
                {
                    SGLogging.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
                }

                if (behavior != null)
                { //If the API is at risk
                    if ((argumentState.taint == VariableTaint.TAINTED || //Tainted values
                        argumentState.taint == VariableTaint.UNKNOWN) &&
                        Array.Exists(behavior.injectablesArguments, element => element == i) //If the current parameter can be injected.
                        )
                    {
                        var newRule = LocaleUtil.GetDescriptor(behavior.localeInjection);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }
                    else if (argumentState.taint == VariableTaint.CONSTANT && //Hard coded value
                        Array.Exists(behavior.passwordArguments, element => element == i) //If the current parameter is a password
                        )
                    {

                        var newRule = LocaleUtil.GetDescriptor(behavior.localePassword);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }

                    else if ( //
                        Array.Exists(behavior.taintFromArguments, element => element == i))
                    {
                        returnState = returnState.merge(argumentState);
                    }
                }

                //TODO: tainted all object passed in argument

                i++;
            }

            //Additionnal analysis by extension
            foreach (var ext in extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            var hasTaintFromArguments = behavior?.taintFromArguments?.Length > 0;
            if (hasTaintFromArguments)
            {
                return returnState;
            }
            else
            {
                return new VariableState(node,VariableTaint.UNKNOWN);
            }

        }

        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitIdentifierName(IdentifierNameSyntax expression, ExecutionState state)
        {
            var value = ResolveIdentifier(expression.Identifier);
            return state.GetValueByIdentifier(value);
        }

        private VariableState VisitBinaryExpression(BinaryExpressionSyntax expression, ExecutionState state)
        {
            VariableState left = VisitExpression(expression.Left, state);
            VariableState right = VisitExpression(expression.Right, state);
            return left.merge(right);
        }

        private VariableState VisitAssignment(AssignmentStatementSyntax node, ExecutionState state)
        {

            var symbol = state.GetSymbol(node.Left);
            MethodBehavior behavior = behaviorRepo.GetMethodBehavior(symbol);

            var variableState = VisitExpression(node.Right, state);

            if (node.Left is IdentifierNameSyntax)
            {
                var assignmentIdentifier = node.Left as IdentifierNameSyntax;
                state.MergeValue(ResolveIdentifier(assignmentIdentifier.Identifier), variableState);
            }

            if (behavior != null && //Injection
                    behavior.isInjectableField &&
                    variableState.taint != VariableTaint.CONSTANT && //Skip safe values
                    variableState.taint != VariableTaint.SAFE)
            {
                var newRule = LocaleUtil.GetDescriptor(behavior.localeInjection);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
            if (behavior != null && //Known Password API
                    behavior.isPasswordField &&
                    variableState.taint == VariableTaint.CONSTANT //Only constant
                    )
            {
                var newRule = LocaleUtil.GetDescriptor(behavior.localePassword);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }


            //TODO: tainted the variable being assign.

            //Additionnal analysis by extension
            foreach (var ext in extensions)
            {
                ext.VisitAssignment(node, state, behavior, symbol, variableState);
            }

            return variableState;
        }

        private VariableState VisitArrayCreation(ArrayCreationExpressionSyntax node, ExecutionState state)
        {
            var arrayInit = node.Initializer;

            var finalState = new VariableState(node,VariableTaint.SAFE);
            if (arrayInit != null)
            {
                foreach (var ex in arrayInit.Initializers)
                {
                    var exprState = VisitExpression(ex, state);
                    finalState = finalState.merge(exprState);
                }
            }
            return finalState;
        }

        private VariableState VisitInterpolatedString(InterpolatedStringExpressionSyntax interpolatedString, ExecutionState state)
        {

            var varState = new VariableState(interpolatedString,VariableTaint.CONSTANT);

            foreach (var content in interpolatedString.Contents)
            {
                var textString = content as InterpolatedStringTextSyntax;
                if (textString != null)
                {
                    varState = varState.merge(new VariableState(textString,VariableTaint.CONSTANT));
                }
                var interpolation = content as InterpolationSyntax;
                if (interpolation != null)
                {
                    var expressionState = VisitExpression(interpolation.Expression, state);
                    varState = varState.merge(expressionState);
                }
            }
            return varState;
        }

        private string ResolveIdentifier(SyntaxToken syntaxToken)
        {
            return syntaxToken.Text;
        }

    }
}
