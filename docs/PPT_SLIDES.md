# LLM Code Analyzer PPT Slides

Source: [PROJECT_REPORT.md](/Users/aggimallaabhishek/Documents/LLM-Code-Analyzer/docs/PROJECT_REPORT.md)

## Slide 1: Title Slide

**Title:** LLM Code Analyzer  
**Subtitle:** AI-Powered Secure Code Analysis System

- Student Name: ____________________
- Roll Number: ____________________
- Department: ____________________
- Institution: ____________________
- Guide / Faculty: ____________________
- Academic Year / Semester: ____________________

## Slide 2: Abstract

- LLM Code Analyzer is a web-based secure code analysis system.
- It combines LLM reasoning with rule-based static analysis.
- It detects vulnerabilities and suggests remediation.
- It supports both single-file and multi-file analysis.
- It provides online and offline execution modes.

## Slide 3: Problem Statement

- Manual security review is slow and depends on expert knowledge.
- Static analyzers are fast but may miss contextual issues.
- LLMs understand context but can be inconsistent alone.
- A hybrid system is needed for practical and intelligent vulnerability detection.

## Slide 4: Objectives

- Build a hybrid code security analyzer.
- Detect common security vulnerabilities.
- Support multiple programming languages.
- Identify attack surfaces and trust boundaries.
- Provide severity-based fix suggestions.
- Make the analyzer available directly without a login step.
- Enable report export in multiple formats.

## Slide 5: Scope of the Project

- Focuses on source-code vulnerability analysis.
- Useful for students, developers, and project demonstrations.
- Helps identify security issues early in the development lifecycle.
- Intended as a prototype and educational tool.
- Not a replacement for full penetration testing or enterprise security suites.

## Slide 6: Technology Stack

- Backend: Python, FastAPI, Pydantic, httpx
- Frontend: React, Vite, React Router, Tailwind CSS, Framer Motion
- AI Layer: Groq online mode and Ollama offline mode
- Reporting: JSON, Markdown, PDF export
- Tooling: ESLint, Vite build, Python compile checks

## Slide 7: Prerequisites and Setup

- Python 3.12+
- Node.js 18+
- Groq API key for online mode or Ollama for offline mode
- Installation flow:
- Clone repository
- Create virtual environment
- Install backend dependencies
- Install frontend dependencies
- Configure `.env`

## Slide 8: System Architecture

- User interacts with the React frontend.
- Frontend communicates with the FastAPI backend.
- Backend contains:
- Analysis API layer
- Static analyzer
- Prompt engine
- LLM service
- Results are returned as structured vulnerability findings.

## Slide 9: Backend Modules

- `backend/app.py`: application startup and route integration
- `backend/config.py`: environment and runtime configuration
- `backend/routes/analyze.py`: single and multi-file analysis APIs
- `backend/services/analyzer.py`: hybrid analysis orchestration
- `backend/services/llm_service.py`: model interaction layer
- `backend/services/static_analyzer.py`: rule-based vulnerability detection
- `backend/models/schemas.py`: request and response models

## Slide 10: Static Analysis Engine

- Detects common security patterns using rules.
- Main categories:
- SQL Injection
- Command Injection
- Dangerous `eval()` and `exec()`
- Hardcoded secrets
- Insecure deserialization
- Weak cryptography
- Debug mode exposure
- Path traversal risks

## Slide 11: LLM Integration

- Static findings are added into a structured prompt.
- The LLM validates findings and adds contextual analysis.
- It returns structured JSON output.
- Output includes:
- Summary
- Risk score
- Vulnerabilities
- Attack surfaces
- Trust boundaries
- Recommendations
- Fixed code suggestions

## Slide 12: Hybrid Analysis Workflow

- Step 1: User submits code or files.
- Step 2: Backend validates request.
- Step 3: Static analyzer scans for known patterns.
- Step 4: Prompt engine prepares LLM input.
- Step 5: LLM performs contextual security analysis.
- Step 6: Analyzer service merges results.
- Step 7: Frontend displays findings and reports.

## Slide 13: Access and Input Validation

- Application pages and analysis APIs are directly accessible without login
- Request validation through Pydantic schemas
- Code length and file count limits
- Security-focused analysis categories aligned with common OWASP risks

## Slide 14: Frontend Features

- Landing page available without signing in
- Dashboard for code input and analysis
- Syntax highlighting for code readability
- Severity-based line highlighting
- Multi-file upload support
- Result cards with fix suggestions
- Copy fixed code option

## Slide 15: Export and Productivity Features

- Export results as JSON
- Export results as Markdown
- Export results as PDF
- Load sample vulnerable code for demo
- Multi-file summary reporting
- User-friendly dashboard workflow

## Slide 16: Development Process

- Requirement analysis and planning
- Backend foundation with FastAPI
- Static analysis engine development
- LLM integration and prompt engineering
- Hybrid analysis orchestration
- Authentication flow removed to provide direct access to the analyzer
- Frontend dashboard development
- Export and reporting features
- Startup automation and documentation

## Slide 17: Run Modes

- Development mode: `./start_dev.sh`
- Online mode: `./start_online.sh`
- Offline mode: `./start_offline.sh`
- Startup scripts automatically clear occupied ports before launch.
- Development mode supports frontend and backend together.

## Slide 18: Functional Workflow

- User opens the application.
- User opens the application directly without a login step.
- User pastes code or uploads files.
- Frontend sends request to backend APIs.
- Backend runs static and LLM-based analysis.
- System returns vulnerabilities, risk score, and recommendations.
- Frontend displays results and export options.

## Slide 19: Features Achieved

- Hybrid analysis using static rules and LLM reasoning
- Detection of 20+ common vulnerability patterns
- Single-file and multi-file analysis
- Attack surface and trust boundary reporting
- Severity-based vulnerability reporting
- Risk score calculation
- Public access to frontend pages and analysis APIs
- Export in JSON, Markdown, and PDF
- Offline analysis support with Ollama

## Slide 20: Testing and Validation

- Frontend lint passed: `npm run lint`
- Frontend production build passed: `npm run build`
- Backend syntax validation passed using `python3 -m py_compile ...`
- Functional testing can be done using sample vulnerable code
- Current repository does not yet contain dedicated unit test files

## Slide 21: Results and Outcomes

- Developed a working web-based code security analyzer
- Combined deterministic and AI-driven security analysis
- Delivered a usable UI for vulnerability reporting
- Added direct access and multi-file support
- Provided practical reporting for academic demonstration

## Slide 22: Challenges and Limitations

- LLM quality depends on selected model and configuration
- Static rules can produce false positives or false negatives
- Frontend bundle size can be optimized further
- Production hardening is still limited
- Automated unit and integration tests are pending

## Slide 23: Future Enhancements

- Analysis history with database storage
- VS Code extension
- GitHub integration
- CI/CD pipeline integration
- Custom vulnerability rules
- Team collaboration features
- Better automated test coverage

## Slide 24: Conclusion

- LLM Code Analyzer is a practical hybrid secure-code review system.
- It combines LLM intelligence with static analysis.
- It improves vulnerability detection and developer awareness.
- It is suitable as an academic major project and a base for future expansion.

## Slide 25: References

- FastAPI Documentation
- React Documentation
- Vite Documentation
- Tailwind CSS Documentation
- Ollama Documentation
- Project README and repository source code

## Slide 26: Thank You

- Thank You
- Questions?
