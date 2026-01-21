# QuLab: Lab 7: Adversarial & Security Test Bank Builder

![Streamlit Logo](https://streamlit.io/images/brand/streamlit-logo-light.svg)

## Project Title and Description

**QuLab: Lab 7: Adversarial & Security Test Bank Builder** is a Streamlit-based educational application designed for **Security Engineers** to understand and practice the process of building robust security test banks for AI systems. This lab focuses on creating, executing, and analyzing adversarial and security tests against mocked AI models (Large Language Models or traditional Machine Learning APIs) to identify vulnerabilities.

The application guides users through:
*   Configuring different types of AI systems (LLM, ML API).
*   Building custom security test cases with specific threat categories and expected safe behaviors.
*   Executing these tests against mocked AI systems that simulate various responses, including security mitigations and failures.
*   Visualizing aggregated findings through a dashboard.
*   Generating audit-ready reports, including an executive summary and an evidence manifest with file integrity checks.

This project is a hands-on exercise to demonstrate the importance of proactive security testing in the AI development lifecycle, especially in contexts like prompt injection, data leakage, and model manipulation.

## Features

The application provides the following key functionalities, organized into a multi-page Streamlit interface:

1.  **AI System Setup**:
    *   Define the AI system under test (e.g., LLM Chatbot, ML Scoring API).
    *   Specify a name for the AI system.
    *   Interact with mocked AI systems (LLM and ML API) to understand their simulated behavior, including heuristic security detections.

2.  **Test Bank Editor**:
    *   Load pre-defined sample test banks (LLM or ML API specific) for quick starts.
    *   Create new, custom security test cases, specifying:
        *   `Test ID`
        *   `Threat Category` (e.g., Prompt Injection, Data Leakage, Malformed Input)
        *   `Test Input` (text for LLM, JSON for ML API)
        *   `Expected Safe Behavior` (text for LLM, JSON fragment for ML API)
        *   `Severity Level` (Low, Medium, High, Critical)
    *   View and manage the current security test bank.
    *   Automatically save the current test bank as a JSON artifact.

3.  **Execute Tests**:
    *   Run all defined test cases against the configured mocked AI system.
    *   Record detailed results for each test, including the actual AI response, pass/fail status, and any detected issues.
    *   Automatically save test execution results and findings summary as JSON artifacts.

4.  **Findings Dashboard**:
    *   View an aggregated summary of test results (total, passed, failed tests).
    *   Visualize failures by `Severity Level` and `Threat Category` using interactive charts.
    *   Browse detailed information for all failed tests, with critical failures highlighted.

5.  **Export Audit-Ready Reports**:
    *   Generate a comprehensive `Executive Summary Report` in Markdown format, outlining key findings, pass/fail rates, and critical vulnerabilities.
    *   Create an `Evidence Manifest` (JSON) that lists all generated artifacts with their SHA-256 hashes for data integrity and auditability.
    *   Download all generated reports and artifacts bundled into a single ZIP file.
    *   Download individual reports as needed.

## Getting Started

Follow these instructions to set up and run the Streamlit application on your local machine.

### Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   `git` (for cloning the repository)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory_name>
    ```
    *(Replace `<repository_url>` and `<repository_directory_name>` with the actual values)*

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: `venv\Scripts\activate`
    ```

3.  **Install the required dependencies:**
    Create a `requirements.txt` file in the root directory with the following content:
    ```
    streamlit
    pandas
    ```
    Then, install them:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Run the Streamlit application:**
    ```bash
    streamlit run app.py
    ```
    This command will open the application in your default web browser (usually at `http://localhost:8501`).

2.  **Navigate the Application:**
    The application is structured into five main sections, accessible via the sidebar:

    *   **System Setup**: Start here to define your AI system (LLM or ML_API) and give it a name. Explore the examples of mocked AI interactions.
    *   **Test Bank Editor**: Build your collection of security test cases. You can load sample banks or create new tests.
    *   **Execute Tests**: Run the tests defined in your test bank against the mocked AI system.
    *   **Findings Dashboard**: Review the aggregated results, identify failed tests, and understand the vulnerability landscape.
    *   **Export Reports**: Generate and download comprehensive audit-ready reports, including an executive summary and an evidence manifest.

    Follow the instructions and prompts within each section to proceed through the security testing workflow.

## Project Structure

```
.
├── app.py                  # Main Streamlit application file
├── source.py               # Contains all core logic, constants, and helper functions
├── requirements.txt        # Python dependencies for the project
├── reports/                # Directory to store generated reports and artifacts (created dynamically)
│   ├── <RUN_ID>/           # Subdirectory for each test run, named by a unique RUN_ID
│       ├── config_snapshot.json          # Snapshot of AI system configuration
│       ├── llm_sample_test_bank.json     # Sample LLM test bank (initial artifact)
│       ├── ml_api_sample_test_bank.json  # Sample ML API test bank (initial artifact)
│       ├── security_test_bank_current_LLM.json  # Current test bank used in a run
│       ├── test_execution_results.json   # Detailed results of test execution
│       ├── findings_summary.json         # Aggregated summary of findings
│       ├── session07_executive_summary.md # Executive summary report
│       ├── evidence_manifest.json        # Manifest of all generated files with SHA256 hashes
│       └── Session_07_<RUN_ID>.zip       # All reports bundled into a zip archive
└── README.md               # This project documentation file
```

## Technology Stack

*   **Python**: The core programming language.
*   **Streamlit**: For building the interactive web application interface.
*   **Pandas**: Used for data manipulation and display (e.g., `st.dataframe`, `st.bar_chart`).
*   **Standard Python Libraries**: `json`, `os`, `datetime`, `zipfile` for file operations, data handling, and archival.

## Contributing

This project is primarily designed as an educational lab. Contributions in the form of bug reports or suggestions for improvements are welcome. Please open an issue on the GitHub repository for any feedback.

For larger contributions, please fork the repository and submit a pull request with a clear description of your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback regarding this lab project, please contact:

*   **QuantUniversity Team**
*   **Website**: [www.quantuniversity.com](https://www.quantuniversity.com)
*   **Email**: info@quantuniversity.com
