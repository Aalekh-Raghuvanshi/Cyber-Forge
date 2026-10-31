"""
AST Route Mapper Service.
Fulfills FR-4: Static Route Map Extractor.
Extracts HTTP endpoints, handler functions, and line ranges from Python (FastAPI/Flask/Django)
and Node.js/Express, and maps them to SAST findings.
"""

import ast
import os
import re
from typing import List, Optional, Dict, Tuple, Any, Set
from backend.models.schemas import RouteEntry, UnifiedFinding
from backend.utils.logger import get_logger

logger = get_logger("route_mapper")


def normalize_file_path(path: str) -> str:
    """Standardizes relative file path representations without stripping directory structure."""
    if not path:
        return ""
    norm = os.path.normpath(path).replace("\\", "/")
    if norm.startswith("./"):
        norm = norm[2:]
    return norm


def normalize_django_pattern(raw_pattern: str) -> str:
    """
    Converts Django path() or re_path() pattern to a standardized URL template.
    Examples:
      'admin/<int:id>/update/' -> '/admin/{id}/update'
      'users/<user_id>/' -> '/users/{user_id}'
      r'^users/(?P<user_id>\d+)/$' -> '/users/{user_id}'
      r'^orders/(?P<order_id>[0-9]+)/items/(?P<item_id>[0-9]+)/$' -> '/orders/{order_id}/items/{item_id}'
    """
    if not raw_pattern:
        return "/"

    p = raw_pattern.strip()
    # Strip regex anchors ^ and $
    if p.startswith("^"):
        p = p[1:]
    if p.endswith("$"):
        p = p[:-1]

    # Convert named regex groups (?P<var_name>[^/]+) -> {var_name}
    p = re.sub(r'\(\?P<([a-zA-Z_][a-zA-Z0-9_]*)>[^\)]+\)', r'{\1}', p)

    # Convert unnamed regex groups (\d+) or ([0-9]+) -> {param}
    p = re.sub(r'\([^\)]+\)', '{param}', p)

    # Convert Django path converter syntax: <int:id> or <slug:article_name> or <id> -> {id}
    p = re.sub(r'<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>', r'{\1}', p)

    # Clean up redundant slashes
    p = re.sub(r'/+', '/', p)

    # Ensure leading slash
    if not p.startswith("/") and p:
        p = f"/{p}"

    # Strip trailing slash if length > 1
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]

    return p or "/"


def normalize_route_path(path: str) -> str:
    """Normalizes URL path for route matching."""
    if not path:
        return "/"
    p = path.strip()
    # Remove query string if any
    if "?" in p:
        p = p.split("?")[0]
    # Remove redundant slashes
    p = re.sub(r'/+', '/', p)
    if not p.startswith("/") and p:
        p = f"/{p}"
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p or "/"


def match_url_to_route(dast_url_path: str, routes: List[RouteEntry]) -> List[RouteEntry]:
    """
    Matches a runtime DAST URL path against static RouteEntry patterns.
    Supports exact matching and parameterized templates (e.g. /admin/{id}/update matches /admin/42/update/).
    """
    if not dast_url_path or not routes:
        return []

    norm_dast = normalize_route_path(dast_url_path)
    dast_segments = [s for s in norm_dast.strip("/").split("/") if s]

    matches: List[RouteEntry] = []

    for route in routes:
        norm_route = normalize_route_path(route.url_path)

        # 1. Exact match
        if norm_dast.lower() == norm_route.lower():
            matches.append(route)
            continue

        # 2. Parameterized segment match
        route_segments = [s for s in norm_route.strip("/").split("/") if s]
        if len(dast_segments) == len(route_segments):
            matched = True
            for d_seg, r_seg in zip(dast_segments, route_segments):
                is_param = (
                    (r_seg.startswith("{") and r_seg.endswith("}")) or
                    (r_seg.startswith("<") and r_seg.endswith(">")) or
                    r_seg.startswith(":")
                )
                if is_param:
                    continue
                if d_seg.lower() != r_seg.lower():
                    matched = False
                    break
            if matched:
                matches.append(route)

    return matches


class PythonFunctionIndexer(ast.NodeVisitor):
    """Indexes all function and async function definitions in a Python AST."""

    def __init__(self, file_path: str):
        self.file_path = normalize_file_path(file_path)
        self.functions: List[Dict[str, Any]] = []

    def _index_func(self, node: ast.AST):
        name = getattr(node, "name", "anonymous")
        start_line = node.lineno
        if hasattr(node, "decorator_list") and node.decorator_list:
            start_line = min([node.lineno] + [d.lineno for d in node.decorator_list])
        end_line = getattr(node, "end_lineno", node.lineno)

        # Collect function calls made inside this function
        called_names: Set[str] = set()
        for subnode in ast.walk(node):
            if isinstance(subnode, ast.Call):
                if isinstance(subnode.func, ast.Name):
                    called_names.add(subnode.func.id)
                elif isinstance(subnode.func, ast.Attribute):
                    called_names.add(subnode.func.attr)

        # Check if function takes 'request' or 'req' as first argument (Django view signature)
        takes_request = False
        args = getattr(node, "args", None)
        if args and args.args:
            first_arg = args.args[0].arg
            if first_arg in ("request", "req"):
                takes_request = True

        self.functions.append({
            "name": name,
            "file": self.file_path,
            "start_line": start_line,
            "end_line": end_line,
            "takes_request": takes_request,
            "calls": called_names,
            "node": node
        })

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._index_func(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._index_func(node)
        self.generic_visit(node)


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
                prefix_val = None
                for kw in call.keywords:
                    if kw.arg in ("prefix", "url_prefix"):
                        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            prefix_val = kw.value.value
                        elif isinstance(kw.value, ast.Str):
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


class DjangoUrlExtractor(ast.NodeVisitor):
    """
    Parses Django urls.py AST for urlpatterns assignments containing
    path(), re_path(), or url() calls.
    """

    def __init__(self, file_path: str, function_index: Dict[str, List[Dict[str, Any]]]):
        self.file_path = normalize_file_path(file_path)
        self.function_index = function_index
        self.routes: List[RouteEntry] = []

    def _extract_str(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.Str):
            return node.s
        return None

    def _extract_target_handler(self, node: ast.AST) -> Optional[str]:
        """Extracts the view function or class name from the second argument of path/re_path."""
        if isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Call):
            # E.g. MyView.as_view()
            if isinstance(node.func, ast.Attribute) and node.func.attr == "as_view":
                if isinstance(node.func.value, ast.Name):
                    return node.func.value.id
                elif isinstance(node.func.value, ast.Attribute):
                    return node.func.value.attr
            elif isinstance(node.func, ast.Name):
                return node.func.id
        elif isinstance(node, (ast.Constant, ast.Str)):
            val = self._extract_str(node)
            if val:
                return val.split(".")[-1]
        return None

    def visit_Assign(self, node: ast.Assign):
        """Detects urlpatterns = [...]"""
        is_urlpatterns = False
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "urlpatterns":
                is_urlpatterns = True
                break

        if is_urlpatterns and isinstance(node.value, (ast.List, ast.Tuple)):
            for elt in node.value.elts:
                self._process_url_entry(elt)

        self.generic_visit(node)

    def _process_url_entry(self, node: ast.AST):
        if not isinstance(node, ast.Call):
            return

        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr

        if call_name in ("path", "re_path", "url") and len(node.args) >= 2:
            pattern_str = self._extract_str(node.args[0])
            if pattern_str is None:
                pattern_str = ""

            handler_name = self._extract_target_handler(node.args[1])
            if not handler_name:
                handler_name = "view_handler"

            normalized_url = normalize_django_pattern(pattern_str)
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

            # Resolve view function location from index
            target_file = self.file_path
            start_line = node.lineno
            end_line = getattr(node, "end_lineno", node.lineno)

            candidates = self.function_index.get(handler_name, [])
            if candidates:
                # Prefer functions that take 'request'
                preferred = next((c for c in candidates if c["takes_request"]), candidates[0])
                target_file = preferred["file"]
                start_line = preferred["start_line"]
                end_line = preferred["end_line"]

            display = f"ANY {normalized_url} -> {handler_name}(), {target_file} lines {start_line} to {end_line}"

            self.routes.append(
                RouteEntry(
                    http_method=methods,
                    url_path=normalized_url,
                    handler_function=handler_name,
                    file=target_file,
                    start_line=start_line,
                    end_line=end_line,
                    display=display
                )
            )


def extract_routes_from_python_code(code: str, file_path: str = "") -> List[RouteEntry]:
    """Parse Python source code AST and return all detected route endpoints."""
    norm_path = normalize_file_path(file_path)
    try:
        tree = ast.parse(code)
    except Exception as e:
        logger.warning(f"Failed to parse AST for {file_path}: {e}")
        return []

    # 1. Flask & FastAPI Decorator Extraction
    extractor = PythonRouteExtractor(code, norm_path)
    extractor.visit(tree)
    if extractor.routes:
        return extractor.routes

    # 2. Django urls.py Extraction
    indexer = PythonFunctionIndexer(norm_path)
    indexer.visit(tree)
    fn_map = {fn["name"]: [fn] for fn in indexer.functions}

    django_extractor = DjangoUrlExtractor(norm_path, fn_map)
    django_extractor.visit(tree)
    if django_extractor.routes:
        return django_extractor.routes

    # 3. Standalone View Function Fallback (def fn(request, ...): -> /{fn_name})
    fallback_routes: List[RouteEntry] = []
    for fn in indexer.functions:
        if fn["takes_request"]:
            fn_name = fn["name"]
            url_path = f"/{fn_name}"
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
            display = f"ANY {url_path} -> {fn_name}(), {norm_path} lines {fn['start_line']} to {fn['end_line']}"
            fallback_routes.append(
                RouteEntry(
                    http_method=methods,
                    url_path=url_path,
                    handler_function=fn_name,
                    file=norm_path,
                    start_line=fn["start_line"],
                    end_line=fn["end_line"],
                    display=display
                )
            )

    return fallback_routes


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

            handler_name = match.group(3) or match.group(5) or "anonymous_handler"

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
    """Extract routes from a single file path, preserving relative file paths."""
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
    Recursively scans folder and extracts all API routes across Flask, FastAPI,
    Express, and Django (including urls.py -> views.py resolution and standalone views).
    Ignores git, virtualenvs, cache, and vendor directories.
    """
    routes: List[RouteEntry] = []
    if not os.path.exists(folder_path):
        return routes

    skip_dirs = {
        ".git", ".svn", "__pycache__", "node_modules", "venv", ".venv",
        "env", "dist", "build", ".next", ".pytest_cache", "migrations",
        "static", "media", "coverage"
    }

    # Step A: Collect Strictly Python (.py) files only
    py_files: List[Tuple[str, str]] = []  # (full_path, rel_path)

    for root, dirs, files in os.walk(folder_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]

        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext != ".py":
                continue

            full_path = os.path.join(root, file)
            # Allow large Django files up to 5MB
            try:
                if os.path.getsize(full_path) > 5 * 1024 * 1024:
                    continue
            except Exception:
                pass

            try:
                rel_path = os.path.relpath(full_path, folder_path)
            except Exception:
                rel_path = full_path
            rel_path = normalize_file_path(rel_path)
            py_files.append((full_path, rel_path))

    # Step B: Index all Python functions across repository for Django view resolution & call-graph linking
    functions_by_name: Dict[str, List[Dict[str, Any]]] = {}
    py_ast_cache: Dict[str, Tuple[ast.AST, str]] = {}

    for full_path, rel_path in py_files:
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                code = f.read()
            tree = ast.parse(code)
            py_ast_cache[rel_path] = (tree, code)

            indexer = PythonFunctionIndexer(rel_path)
            indexer.visit(tree)
            for fn in indexer.functions:
                functions_by_name.setdefault(fn["name"], []).append(fn)
        except Exception:
            continue

    # Step C: Parse Python routes (Flask / FastAPI / Django)
    mapped_views: Set[Tuple[str, str]] = set()  # (file, handler_name)

    for rel_path, (tree, code) in py_ast_cache.items():
        # Check Flask / FastAPI decorators
        extractor = PythonRouteExtractor(code, rel_path)
        extractor.visit(tree)
        for r in extractor.routes:
            routes.append(r)
            mapped_views.add((r.file, r.handler_function))

        # Check Django urls.py
        django_extractor = DjangoUrlExtractor(rel_path, functions_by_name)
        django_extractor.visit(tree)
        for r in django_extractor.routes:
            routes.append(r)
            mapped_views.add((r.file, r.handler_function))

    # Step D: Standalone View File Fallback
    # If any view function taking 'request' is not mapped to a route, register fallback /{fn_name}
    for fn_name, fn_list in functions_by_name.items():
        for fn in fn_list:
            if fn["takes_request"] and (fn["file"], fn["name"]) not in mapped_views:
                url_path = f"/{fn['name']}"
                methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
                display = f"ANY {url_path} -> {fn['name']}(), {fn['file']} lines {fn['start_line']} to {fn['end_line']}"
                routes.append(
                    RouteEntry(
                        http_method=methods,
                        url_path=url_path,
                        handler_function=fn["name"],
                        file=fn["file"],
                        start_line=fn["start_line"],
                        end_line=fn["end_line"],
                        display=display
                    )
                )
                mapped_views.add((fn["file"], fn["name"]))

    # Sort routes by file, start_line
    routes.sort(key=lambda r: (r.file, r.start_line))
    return routes


def paths_match(finding_file: str, route_file: str) -> bool:
    """
    Robust path matching between finding file and route file.
    Does NOT match on naked basename to eliminate cross-subfolder route drift.
    """
    f1 = normalize_file_path(finding_file)
    f2 = normalize_file_path(route_file)

    if not f1 or not f2:
        return False
    if f1 == f2:
        return True
    if f1.endswith(f"/{f2}") or f2.endswith(f"/{f1}"):
        return True
    return False


def find_matching_route(
    finding_file: Optional[str],
    finding_line: Optional[int],
    routes: List[RouteEntry]
) -> Optional[RouteEntry]:
    """
    Finds enclosing route for a finding if finding.file == route.file
    and route.start_line <= finding.line <= route.end_line.
    If the finding is inside a helper function, links to the route handler in that file that calls it.
    Never falls back to a default route, GET /health, or module-level scope.
    """
    if not finding_file or finding_line is None:
        return None

    best_match: Optional[RouteEntry] = None
    min_span = float("inf")
    file_routes: List[RouteEntry] = []

    for route in routes:
        if paths_match(finding_file, route.file):
            file_routes.append(route)
            if route.start_line <= finding_line <= route.end_line:
                span = route.end_line - route.start_line
                if span < min_span:
                    min_span = span
                    best_match = route

    if best_match:
        return best_match

    # Intra-File Helper Function Call-Graph Resolution
    if file_routes:
        # Check if finding_file exists and can be parsed to find enclosing helper function
        target_path = finding_file
        if not os.path.exists(target_path) and file_routes:
            target_path = file_routes[0].file

        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                    code = f.read()
                tree = ast.parse(code)
                indexer = PythonFunctionIndexer(target_path)
                indexer.visit(tree)

                # Find helper function enclosing finding_line
                enclosing_helper = None
                for fn in indexer.functions:
                    if fn["start_line"] <= finding_line <= fn["end_line"]:
                        enclosing_helper = fn
                        break

                if enclosing_helper:
                    helper_name = enclosing_helper["name"]
                    # Find if any route handler in this file calls helper_name
                    for r in file_routes:
                        for fn in indexer.functions:
                            if fn["name"] == r.handler_function and helper_name in fn.get("calls", set()):
                                return r
            except Exception:
                pass

    return None


def enrich_finding_with_route(finding: UnifiedFinding, routes: List[RouteEntry]) -> UnifiedFinding:
    """
    Attaches enclosing route metadata directly onto the SAST finding per FR-4.
    If the finding is outside any route or called helper function, url_path remains None.
    """
    matched = find_matching_route(finding.file, finding.line, routes)
    if matched:
        finding.url_path = matched.url_path
        finding.http_method = matched.http_method[0] if matched.http_method else "GET"
        finding.handler_function = matched.handler_function
        finding.matched_route = matched.display
    else:
        finding.url_path = None
        finding.http_method = None
        finding.handler_function = None
        finding.matched_route = None
    return finding
