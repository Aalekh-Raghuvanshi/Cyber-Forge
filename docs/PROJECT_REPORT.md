# Project Report

## LLM Code Analyzer

**Project Type:** AI-Powered Secure Code Analysis System  
**Repository:** `LLM-Code-Analyzer`  
**Prepared From:** Project README, repository structure, and current implementation  
**Submission Format:** Faculty Project Report Draft  

### Student Details

- **Student Name:** ____________________
- **Roll Number:** ____________________
- **Department:** ____________________
- **Institution:** ____________________
- **Guide / Faculty Name:** ____________________
- **Academic Year / Semester:** ____________________

## Abstract

LLM Code Analyzer is a security-focused software project designed to analyze source code and identify vulnerabilities using a hybrid approach that combines Large Language Models with rule-based static analysis. The system accepts code snippets or multiple source files, detects common weaknesses such as SQL injection, command injection, hardcoded secrets, insecure deserialization, weak cryptography, and unsafe code execution patterns, and then presents the findings in a user-friendly web interface. The project also includes report export functionality, multi-file analysis, syntax-highlighted code viewing, and deployment modes for both online and offline analysis. The application has no login or authentication flow; its frontend and analysis API are directly accessible.

The main goal of the project was to create a practical tool that helps developers, students, and security reviewers detect potential security problems early in the development lifecycle. The final system uses a FastAPI backend, a React + Vite frontend, an LLM integration layer, and a static analysis module. It supports modern security reporting through attack surface mapping, trust boundary identification, vulnerability categorization, and remediation suggestions.

## Keywords

LLM, Static Analysis, Secure Coding, Vulnerability Detection, FastAPI, React, Ollama, Groq, Code Security

## 1. Introduction

Modern software systems often contain security weaknesses caused by unsafe input handling, insecure configuration, or misuse of APIs. Manual review is slow and depends heavily on the reviewer’s experience. Traditional static analyzers are fast and deterministic, but they may miss context-sensitive issues. Large Language Models can reason about code semantics, but they can also be inconsistent if used alone.

This project was developed to solve that gap by combining both approaches. LLM Code Analyzer uses static analysis to detect known vulnerability patterns and an LLM to interpret code context, validate findings, explain risks, and suggest fixes. The result is a practical security analysis workflow that is faster than manual review and more informative than pattern matching alone.

## 2. Problem Statement

The problem addressed by this project is the absence of a simple, interactive, and intelligent tool that can:

1. Analyze code for common security vulnerabilities.
2. Work with both single code snippets and multiple uploaded files.
3. Provide meaningful explanations and remediation guidance.
4. Support both cloud-based and privacy-friendly offline analysis.
5. Present results through a modern interface suitable for demonstration and academic evaluation.

## 3. Objectives

The major objectives of the project were:

1. To build a hybrid code security analyzer using LLM reasoning and static pattern detection.
2. To support multiple programming languages such as Python, JavaScript, Java, C/C++, PHP, Go, and Rust as documented in the project README.
3. To classify vulnerabilities by severity and provide fixed-code suggestions.
4. To identify attack surfaces and trust boundaries in the analyzed code.
5. To provide direct access to the analysis workflow without a login step.
6. To allow single-file and multi-file analysis through a browser-based UI.
7. To support report export in JSON, Markdown, and PDF formats.
8. To provide both online and offline execution modes for broader usability.

## 4. Scope of the Project

The project scope covers secure source-code analysis at the application level. It focuses on developer-facing review rather than runtime monitoring. The system is intended for educational use, security assessment demonstrations, secure coding support, and early-stage vulnerability identification during development.

The project does not replace full manual penetration testing or advanced enterprise SAST/DAST platforms, but it serves as a strong prototype for intelligent secure-code review.

## 5. Technology Stack

| Layer | Technologies Used |
|------|------|
| Backend | Python 3.12+, FastAPI, Pydantic, httpx |
| Frontend | React 19, Vite, React Router, Tailwind CSS, Framer Motion |
| Access | No authentication or login layer |
| AI / Analysis | LLM service abstraction, Ollama, Groq configuration, static analyzer |
| Reporting | JSON export, Markdown export, PDF export using `html2pdf.js` |
| Developer Tooling | ESLint, Vite build, Python bytecode compilation |

### 5.1 Prerequisites

Based on the README, the project requires:

1. Python 3.12 or above
2. Node.js 18 or above
3. Groq API key for online mode or Ollama for offline mode

### 5.2 Installation Procedure

The documented installation sequence for the project is:

```bash
git clone <repository-url>
cd LLM-Code-Analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
cp .env.example .env
```

After this, the `.env` file is configured with the model API keys and runtime settings needed for the selected analysis mode.

### 5.3 Operating Modes

The project supports three documented ways to run the application:

1. Development mode using `./start_dev.sh`
2. Online mode using `./start_online.sh`
3. Offline mode using `./start_offline.sh`

This gives the project flexibility for local development, faculty demonstrations, and privacy-friendly offline execution.

## 6. System Architecture

The project follows a modular client-server architecture.

```text
User
  |
  v
React Frontend
  |
  v
FastAPI Backend
  |
  +--> Analysis API Layer
         |
         +--> Static Analyzer
         |
         +--> Prompt Engine
         |
         +--> LLM Service
                |
                +--> Online Model Configuration
                +--> Offline Ollama Model
```

### Architectural Highlights

1. The frontend handles code input, file upload, results rendering, and report export; users can open it without signing in.
2. The backend exposes public analysis APIs.
3. The analyzer service orchestrates static analysis and LLM analysis.
4. The prompt engine standardizes the JSON structure expected from the LLM.
5. The schemas layer enforces consistent request and response contracts.

## 7. Major Modules Implemented

### 7.1 Backend Modules

| Module | Purpose |
|------|------|
| `backend/app.py` | Initializes FastAPI, middleware, API routes, and SPA serving |
| `backend/config.py` | Loads environment variables and application settings |
| `backend/routes/analyze.py` | Provides single-file and multi-file analysis endpoints |
| `backend/services/analyzer.py` | Coordinates static analysis and LLM-driven reasoning |
| `backend/services/llm_service.py` | Handles LLM requests and response parsing |
| `backend/services/static_analyzer.py` | Detects known vulnerability patterns using rules |
| `backend/models/schemas.py` | Defines request/response data models |
| `backend/utils/prompt_engine.py` | Builds the LLM prompt and response format |

### 7.2 Frontend Modules

| Module | Purpose |
|------|------|
| `frontend/src/App.jsx` | Defines application routing |
| `frontend/src/pages/LandingPage.jsx` | Displays the main landing page |
| `frontend/src/pages/Dashboard.jsx` | Supports code input, analysis, export, and multi-file mode |
| `frontend/src/components/CodeEditor.jsx` | Displays syntax-highlighted code |
| `frontend/src/components/ResultsPanel.jsx` | Shows vulnerabilities, risk score, and recommendations |
| `frontend/src/components/FileUpload.jsx` | Handles multi-file and archive upload |
| `frontend/src/components/MultiFileResults.jsx` | Displays aggregated file-wise analysis |

### 7.3 How the Code Works Internally

This section explains the actual runtime behavior of the current codebase, based on the implementation present in the repository.

#### 7.3.1 Application Bootstrap

1. `backend/app.py` creates the FastAPI application, registers CORS, includes the analysis router, and serves the built React frontend when `frontend/dist` is available.
2. The same file also defines startup logging so the running mode, selected model, and API documentation URL are visible in the terminal during launch.
3. On the client side, `frontend/src/App.jsx` wires the landing page and analyzer routes without a login check.

#### 7.3.2 Public Access Flow

1. The `/` and `/dashboard` routes render directly without checking a user session or token.
2. The frontend sends analysis requests to the API without an authorization header.
3. Analysis endpoints are public and validate request content, code length, and file counts before starting analysis.

#### 7.3.3 Single-File Analysis Flow

1. `frontend/src/pages/Dashboard.jsx` stores the source code, selected language, analysis state, and analysis results in React state variables.
2. When the user clicks **Analyze Code**, the `analyzeCode()` function checks that the editor is not empty, updates the progress text shown in the UI, and sends a `POST /api/analyze` request containing `{ code, language }`.
3. `backend/routes/analyze.py` validates that code is present and within the configured size limit before delegating work to `AnalyzerService`.
4. `backend/services/analyzer.py` is the main orchestration layer. It first runs static analysis, then builds the LLM prompt, optionally appends extra context, calls the LLM service, and finally converts the combined output into a structured `AnalysisResponse`.
5. `backend/services/static_analyzer.py` scans the code line by line using language-specific regular expressions and generic security rules, such as SQL injection, command injection, dangerous `eval()`, hardcoded secrets, insecure deserialization, weak cryptography, and debug mode exposure.
6. `backend/utils/prompt_engine.py` injects the source code and any static findings into a strict JSON-oriented prompt so the model returns predictable fields such as vulnerabilities, attack surfaces, trust boundaries, and recommendations.
7. `backend/services/llm_service.py` sends the prompt to the configured model backend, strips Markdown code fences if necessary, and parses the returned JSON.
8. `backend/models/schemas.py` validates the final response shape through Pydantic models before it is returned to the client.
9. `frontend/src/components/ResultsPanel.jsx` renders the returned summary, risk score, vulnerabilities, attack surfaces, trust boundaries, recommendations, and suggested fixed code.

#### 7.3.4 Multi-File Analysis Flow

1. `frontend/src/components/FileUpload.jsx` accepts individual source files or ZIP archives, reads file content in the browser, infers language from file extension, and skips hidden or irrelevant paths such as `node_modules`, `.git`, and `__pycache__`.
2. The processed files are passed back to `Dashboard.jsx` as objects containing `filename`, `content`, `language`, and file size.
3. When the user starts multi-file analysis, the dashboard sends these files to `POST /api/analyze-multiple`.
4. `backend/routes/analyze.py` loops through the uploaded files, reuses the same `AnalyzerService.analyze_code()` method for each file, and aggregates the results into a `MultiFileAnalysisResponse`.
5. The aggregated response includes per-file findings, total vulnerability count, and an overall risk score computed from the analyzed files.

#### 7.3.5 Reporting and Export Flow

1. `Dashboard.jsx` contains the report-generation functions used by the export menu.
2. JSON export serializes the current result object directly.
3. Markdown export builds a readable report string containing summary data, vulnerability details, attack surfaces, and recommendations.
4. PDF export first generates HTML markup and then converts it to a downloadable PDF in the browser using `html2pdf.js`.
5. `ResultsPanel.jsx` also allows the user to copy the suggested fixed code for a vulnerability using the Clipboard API.

#### 7.3.6 Error Handling and Risk Scoring

1. Empty submissions, oversized code blocks, and excessive multi-file uploads are rejected at the API layer with explicit HTTP errors.
2. `AnalyzerService` catches LLM-specific failures and unexpected exceptions and still returns a structured error response to the frontend.
3. If the LLM does not provide a risk score, the backend calculates one from vulnerability severities and clamps the final value between 0 and 100.
4. Duplicate static findings on the same line are removed before they are returned.

## 8. Development Process From Start to End

This section summarizes the complete development journey in chronological order.

### Phase 1: Requirement Analysis and Planning

At the beginning, the goal was defined clearly: build an intelligent code analyzer that could detect security vulnerabilities and present them in a practical web interface. The README-established feature set included hybrid analysis, multiple model support, multi-file upload, report export, and a modern dashboard.

### Phase 2: Project Setup and Repository Structure

The project was divided into two major parts:

1. A FastAPI backend for API services and analysis logic.
2. A React + Vite frontend for user interaction.

The repository was organized into backend services, routes, models, utilities, frontend pages, frontend components, sample data, and startup scripts. This separation improved maintainability and kept the architecture modular.

### Phase 3: Backend Foundation

The backend was implemented using FastAPI. Core setup included:

1. Application bootstrap and lifespan events.
2. CORS configuration for frontend communication.
3. API route registration.
4. Static frontend serving when the production build is available.

This phase established the base platform on which all security analysis features were built.

### Phase 4: Static Analysis Engine

A dedicated static analyzer module was developed to detect common vulnerability patterns using rule-based pattern matching. It currently includes patterns for issues such as:

1. SQL injection
2. Command injection
3. Dangerous `eval()` and `exec()`
4. Hardcoded credentials and tokens
5. Insecure deserialization
6. Weak cryptography such as MD5 and SHA1
7. Debug mode exposure
8. Path traversal risks

Language detection logic was also added so the analyzer can infer the likely source language when the user selects automatic mode.

### Phase 5: LLM Integration and Prompt Engineering

After static analysis, the next step was integrating an LLM service layer. The objective of this layer was not only to flag issues, but also to:

1. Understand code context.
2. Validate whether rule-based findings represent real vulnerabilities.
3. Produce structured JSON output.
4. Generate summaries, risk scores, recommendations, and fixed-code examples.

To support this, a prompt engine was implemented that sends the source code and static findings to the model and requires a structured JSON response containing attack surfaces, trust boundaries, vulnerabilities, and recommendations.

### Phase 6: Hybrid Analysis Orchestration

The analyzer service was then designed as the core orchestration layer. Its workflow is:

1. Receive code and metadata.
2. Run static analysis first.
3. Build the LLM prompt using code plus static findings.
4. Call the configured model service.
5. Parse the model response.
6. Merge results into a unified analysis response.
7. Compute or validate an overall risk score.

This hybrid design is the central contribution of the project.

### Phase 7: Authentication Removal

The earlier Google OAuth and JWT login flow was removed so the analyzer can be used directly. The change removes the OAuth routes, session middleware, token handling, login page, and protected frontend routes. Analysis endpoints and application pages are now public.

### Phase 8: Frontend Interface Development

The frontend was built using React and Vite with a security-themed interface. Development focused on clarity and usability. Major UI work included:

1. Landing page highlighting project capabilities.
2. Dashboard for entering or pasting source code.
3. Syntax-highlighted code display.
4. Severity-based line highlighting.
5. Result cards for vulnerabilities and fix suggestions.
6. Risk score presentation.
7. Upload support for multiple files and ZIP-based workflows.

This phase made the project usable for demonstration and end users.

### Phase 9: Report Export and Productivity Features

Once core analysis was working, reporting and usability features were added:

1. Export analysis results as JSON.
2. Export analysis results as Markdown.
3. Export analysis results as PDF.
4. Copy fixed code snippets.
5. Support one-click sample loading for demonstration.

These additions improved the project’s usefulness for submissions, presentations, and security documentation.

### Phase 10: Startup Automation and Execution Modes

To simplify execution, shell scripts were created for different usage scenarios:

1. `start_dev.sh` for frontend + backend development with hot reload.
2. `start_online.sh` for online model execution on port 8000.
3. `start_offline.sh` for offline Ollama execution on port 8001.

These scripts also clean up previously running processes on the required ports before launching the application.

### Phase 11: Documentation and User Guidance

The README was expanded to include:

1. Prerequisites and installation steps
2. Authentication removal and direct-access setup
3. Environment variable configuration
4. API usage examples
5. Project structure
6. Supported vulnerabilities
7. Offline mode instructions
8. Troubleshooting guidance
9. Sample vulnerable code
10. Development and quality commands

This documentation made the project easier to install, demonstrate, and evaluate.

### Phase 12: Validation and Final Review

The final stage focused on validating that the project can be built and checked successfully. On **April 7, 2026**, the following repository-level checks were run successfully in the current workspace:

1. Frontend lint: `npm run lint`
2. Frontend production build: `npm run build`
3. Backend syntax validation: `python3 -m py_compile backend/*.py backend/routes/*.py backend/services/*.py backend/models/*.py backend/utils/*.py`

The frontend build completed successfully. Vite reported a large chunk warning related to bundled client assets, which is a performance optimization concern rather than a build failure.

## 9. Functional Workflow of the System

The working flow of the final application is as follows:

1. The user opens the application directly.
2. The user pastes a code snippet or uploads multiple files.
3. The frontend sends the request to the analysis API.
4. The backend validates the request and triggers the analyzer service.
5. Static analysis scans the code for known patterns.
6. The prompt engine constructs the LLM request.
7. The LLM generates structured analysis results.
8. The backend returns vulnerabilities, summaries, trust boundaries, attack surfaces, recommendations, and risk score.
9. The frontend renders the results and allows export or copy operations.

## 10. Security-Oriented Design Decisions

The project was built around secure-coding analysis, so several security-focused decisions were included in the implementation:

1. Direct public access to the application and analysis API without user accounts.
2. Request validation through Pydantic schemas.
3. Maximum code-length restriction for analysis requests.
4. Maximum file-count restriction for batch analysis.
5. Structured risk scoring and severity classification.
6. Static analysis rules aligned with common OWASP-style vulnerability categories such as injection, insecure deserialization, weak cryptography, and secret exposure.

For a production-hardening phase, additional steps such as restrictive CORS, HTTPS deployment, and more extensive automated tests would be appropriate.

## 11. Features Achieved

According to the README and current repository implementation, the following major features were completed:

1. Hybrid analysis using LLM reasoning and static analysis.
2. Detection of 20+ common vulnerability patterns.
3. Support for single-file and multi-file analysis.
4. Attack surface and trust boundary reporting.
5. Severity-based vulnerability presentation.
6. Risk score calculation.
7. Public access to frontend pages and analysis endpoints without login.
8. Syntax highlighting and vulnerable line highlighting.
9. Export to JSON, Markdown, and PDF.
10. Copy-to-clipboard support for fixed code.
11. Startup scripts for development, online, and offline modes.
12. Offline analysis option using Ollama.
13. Integrated frontend and backend deployment flow.

## 12. Testing and Validation Summary

### 12.1 Validation Done

The project documentation and current repository support the following validation activities:

1. Running the frontend linter.
2. Building the frontend for production.
3. Verifying backend Python files compile successfully.
4. Using provided sample vulnerable code to test detection quality.
5. Exercising analysis, upload, and export workflows manually through the UI.

### 12.2 Current Testing Observation

The repository does **not** currently contain dedicated automated unit test files. Therefore, the present verification level is based on linting, build validation, backend syntax checks, and functional/manual testing flows. For a future academic or production extension, adding unit tests for the analyzer service, auth helpers, and frontend components would strengthen the project significantly.

## 13. Results and Outcome

The project successfully produced a working secure-code analysis platform with the following outcomes:

1. A usable web-based dashboard for vulnerability analysis.
2. A backend that accepts code and returns structured findings.
3. A hybrid analysis pipeline that combines deterministic and AI-driven methods.
4. A reporting system that converts technical findings into submission-ready outputs.
5. A documented setup process for both online and offline execution.

The overall outcome demonstrates that LLM-assisted security analysis can be integrated effectively with traditional static detection to improve developer productivity and security awareness.

## 14. Challenges and Limitations

During or after implementation, the following practical limitations are relevant:

1. LLM quality depends on model availability and configuration.
2. Static analysis rules are pattern-based and may produce false positives or false negatives.
3. Large client-side report generation libraries increase frontend bundle size.
4. Full production security hardening still requires tighter deployment settings.
5. Automated unit and integration testing are not yet fully implemented in the repository.
6. The tool is best suited for early detection and developer guidance, not as a complete replacement for expert security auditing.

## 15. Future Enhancements

The README roadmap and repository direction suggest the following future work:

1. Analysis history with database storage
2. VS Code extension
3. GitHub integration
4. CI/CD pipeline integration
5. Custom vulnerability rules
6. Team collaboration features
7. Theme improvements and additional UI refinements

Additional technical improvements could include unit tests, stricter backend security configuration, bundle optimization, and richer language coverage validation.

## 16. Conclusion

LLM Code Analyzer is a well-structured academic and practical project that demonstrates how AI can be combined with traditional static analysis to improve source-code security review. Starting from the idea of intelligent vulnerability detection, the project progressed through planning, modular backend development, LLM integration, direct-access frontend design, multi-file support, report export, execution automation, and final build validation.

The final system includes a complete web interface, API-driven backend, vulnerability analysis engine, and exportable reports. It does not require accounts or login; application pages and analysis endpoints are public.

## Appendix A: Main API Endpoints

| Endpoint | Method | Purpose |
|------|------|------|
| `/api/analyze` | POST | Analyzes a single code snippet |
| `/api/analyze-multiple` | POST | Analyzes multiple files |
| `/api/health` | GET | Returns service health |
| `/api/config` | GET | Returns non-sensitive configuration |

## Appendix B: Faculty Presentation Summary

If a short viva or presentation summary is needed, the project can be described in one paragraph as follows:

> LLM Code Analyzer is an AI-assisted web application for source-code security analysis. It uses a FastAPI backend and a React frontend to analyze code snippets or multiple files, detect vulnerabilities through static rules and LLM reasoning, classify issues by severity, suggest fixes, and export results as JSON, Markdown, or PDF. Application pages and analysis endpoints are directly accessible without login, and offline analysis is supported through Ollama.

## References

1. FastAPI Documentation
2. React Documentation
3. Vite Documentation
4. Tailwind CSS Documentation
5. Ollama Documentation
6. Project README and repository source code
