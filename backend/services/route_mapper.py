"""
AST Route Mapper Service.
Fulfills FR-4: Static Route Map Extractor.
Extracts HTTP endpoints, handler functions, and line ranges from Python (FastAPI/Flask)
and Node.js/Express, and maps them to SAST findings.
"""

import ast
import os
import re
from typing import List, Optional, Dict, Tuple
from backend.models.schemas import RouteEntry, UnifiedFinding
from backend.utils.logger import get_logger

logger = get_logger("route_mapper")


def normalize_file_path(path: str) -> str:
    """Standardizes relative file path representations."""
    if not path:
        return ""
    norm = os.path.normpath(path).replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    return norm


class PythonRouteExtractor(ast.NodeVisitor):
    """AST Visitor that extracts FastAPI and Flask route definitions."""

    def __init__(self, code: str, file_path: str):
        self.code = code
        self.file_path = normalize_file_path(file_path)
        self.routes: List[RouteEntry] = []
        self.prefixes: Dict[str, str] = {}  # var_name -> prefix (e.g. router = APIRouter(prefix="/api"))

    def visit_Assign(self, node: ast.Assign):
        """Track router and blueprint prefix definitions."""
        if isinstance(node.value, ast.Call):
            call = node.value
            func_name = ""
            if isinstance(call.func, ast.Name):
                func_name = call.func.id
            elif isinstance(call.func, ast.Attribute):
                func_name = call.func.attr

            if func_name in ("APIRouter", "Blueprint"):
                # Look for prefix / url_prefix keyword
                prefix_val = None
                for kw in call.keywords:
                    if kw.arg in ("prefix", "url_prefix"):
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            prefix_val = kw.value.value
                        elif isinstance(kw.value, ast.Str):  # Python <3.8 compatibility
                            prefix_val = kw.value.s

                if prefix_val:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.prefixes[target.id] = prefix_val

        self.generic_visit(node)

    def _extract_string_value(self, node: ast.AST) -> Optional[str]:
        """Extract literal string from AST constant or Str node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):
            return node.s
        return None

    def _extract_methods_from_decorator(self, decorator: ast.Call, attr_name: str) -> List[str]:
        """Extract HTTP methods from decorator attribute or kwargs."""
        lower_attr = attr_name.lower()
        http_verbs = {"get", "post", "put", "delete", "patch", "options", "head"}

        if lower_attr in http_verbs:
            return [lower_attr.upper()]

        if lower_attr in ("route", "api_route"):
            # Check methods=['GET', 'POST']
            for kw in decorator.keywords:
                if kw.arg == "methods":
                    if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        methods = []
                        for elt in kw.value.elts:
                            val = self._extract_string_value(elt)
                            if val:
                                methods.append(val.upper())
                        if methods:
                            return methods
            # Flask default for @app.route is GET
            return ["GET"]

        return ["GET"]

    def _combine_prefix_and_path(self, prefix: Optional[str], path: str) -> str:
        """Combine prefix and route path cleanly."""
        if not prefix:
            return path if path.startswith("/") else f"/{path}"
        p = prefix.rstrip("/")
        sub = path.lstrip("/")
        return f"{p}/{sub}"

    def _handle_function(self, node: ast.AST):
        """Analyze function decorators for route definitions."""
        if not hasattr(node, "decorator_list"):
            return

        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue

            call = decorator
            attr_name = ""
            receiver_name = ""

            if isinstance(call.func, ast.Attribute):
                attr_name = call.func.attr
                if isinstance(call.func.value, ast.Name):
                    receiver_name = call.func.value.id
            elif isinstance(call.func, ast.Name):
                attr_name = call.func.id

            supported_attrs = {
                "get", "post", "put", "delete", "patch", "options", "head",
                "route", "api_route"
            }

            if attr_name.lower() in supported_attrs:
                # Extract path from first argument or 'path' / 'rule' keyword
                path_str = None
                if call.args:
                    path_str = self._extract_string_value(call.args[0])
                if not path_str:
                    for kw in call.keywords:
                        if kw.arg in ("path", "rule"):
                            path_str = self._extract_string_value(kw.value)

                if path_str is not None:
                    methods = self._extract_methods_from_decorator(call, attr_name)
                    prefix = self.prefixes.get(receiver_name, "")
                    full_path = self._combine_prefix_and_path(prefix, path_str)

                    # Start line is the first decorator line
                    start_line = decorator.lineno
                    if node.decorator_list:
                        start_line = min(d.lineno for d in node.decorator_list)

                    end_line = getattr(node, "end_lineno", node.lineno)
                    handler_name = getattr(node, "name", "handler")

                    methods_display = ", ".join(methods)
                    display = f"{methods_display} {full_path} -> {handler_name}(), {self.file_path} lines {start_line} to {end_line}"

                    self.routes.append(
                        RouteEntry(
                            http_method=methods,
                            url_path=full_path,
                            handler_function=handler_name,
                            file=self.file_path,
                            start_line=start_line,
                            end_line=end_line,
                            display=display
                        )
                    )

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._handle_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._handle_function(node)
        self.generic_visit(node)


def extract_routes_from_python_code(code: str, file_path: str = "") -> List[RouteEntry]:
    """Parse Python source code AST and return all detected route endpoints."""
    try:
        tree = ast.parse(code)
        extractor = PythonRouteExtractor(code, file_path)
        extractor.visit(tree)
        return extractor.routes
    except Exception as e:
        logger.warning(f"Failed to parse AST for {file_path}: {e}")
        return []


def extract_routes_from_js_code(code: str, file_path: str = "") -> List[RouteEntry]:
    """
    Regex fallback for Node.js/Express route declarations:
    app.get('/path', handler) / router.post('/path', (req, res) => ...)
    """
    routes: List[RouteEntry] = []
    lines = code.split("\n")
    norm_file = normalize_file_path(file_path)

    express_pattern = re.compile(
        r'(?:app|router|api)\.(get|post|put|delete|patch|all)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*,\s*(?:async\s*)?(?:function\s*([a-zA-Z0-9_$]+)?|\(?([a-zA-Z0-9_$,\s]*)\)?\s*=>|([a-zA-Z0-9_$]+))?',
        re.IGNORECASE
    )

    for i, line in enumerate(lines, 1):
        match = express_pattern.search(line)
        if match:
            method_str = match.group(1).upper()
            methods = ["GET", "POST", "PUT", "DELETE"] if method_str == "ALL" else [method_str]
            url_path = match.group(2)
            if not url_path.startswith("/"):
                url_path = f"/{url_path}"

            # Handler name heuristic
            handler_name = match.group(3) or match.group(5) or "anonymous_handler"

            # Determine approximate end line by bracket balancing or small block
            start_line = i
            end_line = i
            brace_count = 0
            found_open = False
            for j in range(i - 1, min(len(lines), i + 80)):
                cur_line = lines[j]
                brace_count += cur_line.count("{") - cur_line.count("}")
                if "{" in cur_line:
                    found_open = True
                if found_open and brace_count <= 0:
                    end_line = j + 1
                    break
            if end_line == start_line:
                end_line = min(len(lines), start_line + 15)

            display = f"{', '.join(methods)} {url_path} -> {handler_name}(), {norm_file} lines {start_line} to {end_line}"
            routes.append(
                RouteEntry(
                    http_method=methods,
                    url_path=url_path,
                    handler_function=handler_name,
                    file=norm_file,
                    start_line=start_line,
                    end_line=end_line,
                    display=display
                )
            )

    return routes


def extract_routes_from_file(file_path: str, base_dir: Optional[str] = None) -> List[RouteEntry]:
    """Extract routes from a single file path."""
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        return []

    rel_path = file_path
    if base_dir:
        try:
            rel_path = os.path.relpath(file_path, base_dir)
        except Exception:
            rel_path = file_path
    rel_path = normalize_file_path(rel_path)

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code = f.read()
    except Exception as e:
        logger.warning(f"Could not read file {file_path}: {e}")
        return []

    if file_path.endswith(".py"):
        return extract_routes_from_python_code(code, rel_path)
    elif file_path.endswith((".js", ".ts", ".mjs", ".jsx", ".tsx")):
        return extract_routes_from_js_code(code, rel_path)
    return []


def extract_routes_from_folder(folder_path: str) -> List[RouteEntry]:
    """
    Recursively scans folder and extracts all API routes.
    Ignores git, virtualenvs, cache, and vendor directories.
    """
    routes: List[RouteEntry] = []
    if not os.path.exists(folder_path):
        return routes

    skip_dirs = {
        ".git", ".svn", "__pycache__", "node_modules", "venv", ".venv",
        "env", "dist", "build", ".next", ".pytest_cache"
    }

    for root, dirs, files in os.walk(folder_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in (".py", ".js", ".ts", ".mjs"):
                full_path = os.path.join(root, file)
                file_routes = extract_routes_from_file(full_path, base_dir=folder_path)
                routes.extend(file_routes)

    # Sort routes by file, start_line
    routes.sort(key=lambda r: (r.file, r.start_line))
    return routes


def paths_match(finding_file: str, route_file: str) -> bool:
    """Robust path matching between finding file and route file."""
    f1 = normalize_file_path(finding_file)
    f2 = normalize_file_path(route_file)

    if not f1 or not f2:
        return False
    if f1 == f2:
        return True
    if f1.endswith(f"/{f2}") or f2.endswith(f"/{f1}"):
        return True
    return os.path.basename(f1) == os.path.basename(f2)


def find_matching_route(
    finding_file: Optional[str],
    finding_line: Optional[int],
    routes: List[RouteEntry]
) -> Optional[RouteEntry]:
    """
    Finds enclosing route for a finding if finding.file == route.file
    and route.start_line <= finding.line <= route.end_line.
    Returns the narrowest matching route.
    """
    if not finding_file or finding_line is None:
        return None

    best_match: Optional[RouteEntry] = None
    min_span = float("inf")

    for route in routes:
        if paths_match(finding_file, route.file):
            if route.start_line <= finding_line <= route.end_line:
                span = route.end_line - route.start_line
                if span < min_span:
                    min_span = span
                    best_match = route

    return best_match


def enrich_finding_with_route(finding: UnifiedFinding, routes: List[RouteEntry]) -> UnifiedFinding:
    """Attaches enclosing route metadata directly onto the SAST finding per FR-4."""
    matched = find_matching_route(finding.file, finding.line, routes)
    if matched:
        finding.url_path = matched.url_path
        finding.http_method = matched.http_method[0] if matched.http_method else "GET"
        finding.handler_function = matched.handler_function
    return finding
