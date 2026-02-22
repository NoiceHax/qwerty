"""Unsafe SQL construction detection using AST and regex."""

from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List

Finding = Dict[str, Any]

# Regex patterns for string-concatenated SQL
_SQL_CONCAT_PATTERNS = [
    # f-string SQL
    re.compile(r'''(execute|query|cursor\.execute)\s*\(\s*f['"](SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)''', re.I),
    # String concatenation with SQL keywords
    re.compile(r'''(execute|query|cursor\.execute)\s*\(\s*['"](SELECT|INSERT|UPDATE|DELETE).*['"]\s*\+''', re.I),
    # .format() with SQL
    re.compile(r'''(execute|query)\s*\(\s*['"](SELECT|INSERT|UPDATE|DELETE).*['"]\.format\s*\(''', re.I),
    # % formatting with SQL
    re.compile(r'''(execute|query)\s*\(\s*['"](SELECT|INSERT|UPDATE|DELETE).*['"]\s*%''', re.I),
    # Raw SQL in ORM
    re.compile(r'''\.raw\s*\(\s*f['"](SELECT|INSERT|UPDATE|DELETE)''', re.I),
    re.compile(r'''text\s*\(\s*f['"](SELECT|INSERT|UPDATE|DELETE)''', re.I),
]

# JS/TS patterns
_JS_SQL_PATTERNS = [
    re.compile(r'''(query|execute)\s*\(\s*`(SELECT|INSERT|UPDATE|DELETE).*\$\{''', re.I),
    re.compile(r'''(query|execute)\s*\(\s*['"](SELECT|INSERT|UPDATE|DELETE).*['"]\s*\+''', re.I),
]


class SQLAnalyzer:
    """Detects unsafe SQL construction patterns in source code."""

    def analyze(self, file_contents: Dict[str, str], repo_root: str) -> List[Finding]:
        findings: List[Finding] = []

        for filepath, content in file_contents.items():
            rel_path = os.path.relpath(filepath, repo_root)
            ext = os.path.splitext(filepath)[1].lower()

            # Python AST-based analysis
            if ext == ".py":
                ast_findings = self._analyze_python_ast(content, rel_path)
                findings.extend(ast_findings)

            # Regex-based analysis for Python
            if ext == ".py":
                for line_num, line in enumerate(content.splitlines(), 1):
                    for pattern in _SQL_CONCAT_PATTERNS:
                        if pattern.search(line):
                            findings.append(self._make_finding(
                                rel_path, line_num, line.strip(),
                                "SQL query constructed with string formatting",
                            ))
                            break

            # JS/TS analysis
            if ext in (".js", ".ts", ".jsx", ".tsx"):
                for line_num, line in enumerate(content.splitlines(), 1):
                    for pattern in _JS_SQL_PATTERNS:
                        if pattern.search(line):
                            findings.append(self._make_finding(
                                rel_path, line_num, line.strip(),
                                "SQL query constructed with template literals or concatenation",
                            ))
                            break

        return findings

    def _analyze_python_ast(self, content: str, rel_path: str) -> List[Finding]:
        """Use Python AST to find SQL injection-prone patterns."""
        findings: List[Finding] = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Look for cursor.execute() calls
            if isinstance(node, ast.Call):
                func = node.func
                func_name = self._get_call_name(func)

                if func_name and any(kw in func_name for kw in ("execute", "raw", "query")):
                    if node.args:
                        first_arg = node.args[0]
                        # Check if the first arg is an f-string
                        if isinstance(first_arg, ast.JoinedStr):
                            findings.append(self._make_finding(
                                rel_path, node.lineno,
                                f"Line {node.lineno}: f-string used in {func_name}()",
                                f"f-string used in {func_name}() — vulnerable to SQL injection",
                            ))
                        # Check if it's string concatenation (BinOp with Add)
                        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                            findings.append(self._make_finding(
                                rel_path, node.lineno,
                                f"Line {node.lineno}: string concatenation in {func_name}()",
                                f"String concatenation in {func_name}() — vulnerable to SQL injection",
                            ))
                        # Check for .format() call
                        elif (isinstance(first_arg, ast.Call)
                              and isinstance(first_arg.func, ast.Attribute)
                              and first_arg.func.attr == "format"):
                            findings.append(self._make_finding(
                                rel_path, node.lineno,
                                f"Line {node.lineno}: .format() in {func_name}()",
                                f".format() used in {func_name}() — vulnerable to SQL injection",
                            ))
                        # Check for % formatting
                        elif (isinstance(first_arg, ast.BinOp)
                              and isinstance(first_arg.op, ast.Mod)):
                            findings.append(self._make_finding(
                                rel_path, node.lineno,
                                f"Line {node.lineno}: % formatting in {func_name}()",
                                f"% formatting used in {func_name}() — vulnerable to SQL injection",
                            ))

        return findings

    @staticmethod
    def _get_call_name(func) -> str | None:
        if isinstance(func, ast.Attribute):
            return func.attr
        elif isinstance(func, ast.Name):
            return func.id
        return None

    @staticmethod
    def _make_finding(rel_path: str, line_num: int, evidence: str, detail: str) -> Finding:
        return {
            "vuln_type": "unsafe_sql",
            "title": f"Unsafe SQL construction in {rel_path}",
            "description": detail,
            "severity": "high",
            "confidence": "high",
            "detection_source": "static:sql_analyzer",
            "remediation": (
                "Use parameterized queries (prepared statements) instead of string formatting. "
                "Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            ),
            "evidence": evidence,
            "location": f"{rel_path}:{line_num}",
        }
