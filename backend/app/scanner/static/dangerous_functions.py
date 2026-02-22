"""Dangerous function usage detection."""

from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List

Finding = Dict[str, Any]

# Dangerous Python functions
_PYTHON_DANGEROUS = {
    "eval": {
        "severity": "high",
        "description": "eval() executes arbitrary Python code and is a major security risk if user input is involved.",
        "remediation": "Use ast.literal_eval() for safe evaluation, or use JSON parsing instead.",
    },
    "exec": {
        "severity": "high",
        "description": "exec() executes arbitrary Python code. Avoid it entirely if possible.",
        "remediation": "Find an alternative that doesn't require dynamic code execution.",
    },
    "compile": {
        "severity": "medium",
        "description": "compile() creates code objects that can be executed. Risky with user input.",
        "remediation": "Avoid compile() with untrusted input. Use safer alternatives.",
    },
    "__import__": {
        "severity": "medium",
        "description": "__import__() allows dynamic import of modules, which can be exploited.",
        "remediation": "Use explicit imports instead of __import__().",
    },
}

# Dangerous module.function calls
_PYTHON_DANGEROUS_CALLS = {
    ("pickle", "loads"): {
        "severity": "critical",
        "description": "pickle.loads() deserializes untrusted data and can execute arbitrary code.",
        "remediation": "Never unpickle data from untrusted sources. Use JSON or MessagePack.",
    },
    ("pickle", "load"): {
        "severity": "critical",
        "description": "pickle.load() deserializes from file and can execute arbitrary code.",
        "remediation": "Never unpickle data from untrusted sources. Use JSON or MessagePack.",
    },
    ("yaml", "load"): {
        "severity": "high",
        "description": "yaml.load() without Loader parameter can execute arbitrary Python code.",
        "remediation": "Use yaml.safe_load() instead of yaml.load().",
    },
    ("marshal", "loads"): {
        "severity": "high",
        "description": "marshal.loads() can execute arbitrary code via crafted data.",
        "remediation": "Avoid marshal for untrusted data. Use JSON.",
    },
    ("os", "system"): {
        "severity": "high",
        "description": "os.system() executes shell commands and is vulnerable to command injection.",
        "remediation": "Use subprocess.run() with shell=False and a list of arguments.",
    },
    ("os", "popen"): {
        "severity": "high",
        "description": "os.popen() is vulnerable to command injection.",
        "remediation": "Use subprocess.run() with shell=False.",
    },
    ("subprocess", "call"): {
        "severity": "medium",
        "description": "subprocess.call() with shell=True is vulnerable to command injection.",
        "remediation": "Use subprocess.run() with shell=False and pass arguments as a list.",
    },
    ("subprocess", "Popen"): {
        "severity": "medium",
        "description": "subprocess.Popen() with shell=True is vulnerable to command injection.",
        "remediation": "Set shell=False and pass arguments as a list.",
    },
}

# JS/TS dangerous patterns
_JS_DANGEROUS_PATTERNS = [
    (re.compile(r'\beval\s*\(', re.I), "eval()", "high",
     "eval() executes arbitrary JavaScript. Use JSON.parse() or safer alternatives."),
    (re.compile(r'new\s+Function\s*\(', re.I), "new Function()", "high",
     "new Function() is similar to eval(). Avoid dynamic code generation."),
    (re.compile(r'child_process', re.I), "child_process usage", "medium",
     "Ensure child_process commands don't include user input. Use parameterized arguments."),
    (re.compile(r'\.innerHTML\s*=', re.I), "innerHTML assignment", "medium",
     "Direct innerHTML assignment is vulnerable to XSS. Use textContent or sanitize input."),
    (re.compile(r'document\.write\s*\(', re.I), "document.write()", "medium",
     "document.write() can introduce XSS vulnerabilities. Use DOM manipulation instead."),
    (re.compile(r'dangerouslySetInnerHTML', re.I), "dangerouslySetInnerHTML", "medium",
     "React's dangerouslySetInnerHTML bypasses XSS protection. Sanitize input with DOMPurify."),
]


class DangerousFunctionDetector:
    """Detects usage of dangerous functions in source code."""

    def analyze(self, file_contents: Dict[str, str], repo_root: str) -> List[Finding]:
        findings: List[Finding] = []

        for filepath, content in file_contents.items():
            rel_path = os.path.relpath(filepath, repo_root)
            ext = os.path.splitext(filepath)[1].lower()

            if ext == ".py":
                findings.extend(self._analyze_python(content, rel_path))

            if ext in (".js", ".ts", ".jsx", ".tsx"):
                findings.extend(self._analyze_js(content, rel_path))

        return findings

    def _analyze_python(self, content: str, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Direct function calls: eval(), exec(), etc.
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in _PYTHON_DANGEROUS:
                        info = _PYTHON_DANGEROUS[func_name]
                        findings.append({
                            "vuln_type": "dangerous_function",
                            "title": f"Dangerous function {func_name}() used in {rel_path}",
                            "description": info["description"],
                            "severity": info["severity"],
                            "confidence": "high",
                            "detection_source": "static:dangerous_functions",
                            "remediation": info["remediation"],
                            "location": f"{rel_path}:{node.lineno}",
                        })

                # Attribute calls: pickle.loads(), os.system(), etc.
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        module = node.func.value.id
                        func = node.func.attr
                        key = (module, func)
                        if key in _PYTHON_DANGEROUS_CALLS:
                            info = _PYTHON_DANGEROUS_CALLS[key]

                            # Special handling for subprocess with shell=True
                            if module == "subprocess":
                                has_shell_true = any(
                                    isinstance(kw, ast.keyword)
                                    and kw.arg == "shell"
                                    and isinstance(kw.value, ast.Constant)
                                    and kw.value.value is True
                                    for kw in node.keywords
                                )
                                if not has_shell_true:
                                    continue  # subprocess without shell=True is fine

                            # Special handling for yaml.load with Loader
                            if key == ("yaml", "load"):
                                has_loader = any(
                                    isinstance(kw, ast.keyword) and kw.arg == "Loader"
                                    for kw in node.keywords
                                )
                                if has_loader:
                                    continue  # yaml.load with Loader is fine

                            findings.append({
                                "vuln_type": "dangerous_function",
                                "title": f"Dangerous call {module}.{func}() in {rel_path}",
                                "description": info["description"],
                                "severity": info["severity"],
                                "confidence": "high",
                                "detection_source": "static:dangerous_functions",
                                "remediation": info["remediation"],
                                "location": f"{rel_path}:{node.lineno}",
                            })

        return findings

    def _analyze_js(self, content: str, rel_path: str) -> List[Finding]:
        findings: List[Finding] = []

        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, name, severity, remediation in _JS_DANGEROUS_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "vuln_type": "dangerous_function",
                        "title": f"Dangerous {name} in {rel_path}",
                        "description": f"{name} detected at line {line_num}.",
                        "severity": severity,
                        "confidence": "high",
                        "detection_source": "static:dangerous_functions",
                        "remediation": remediation,
                        "evidence": line.strip()[:200],
                        "location": f"{rel_path}:{line_num}",
                    })
                    break

        return findings
