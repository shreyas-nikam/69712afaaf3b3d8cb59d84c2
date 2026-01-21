id: 69712afaaf3b3d8cb59d84c2_documentation
summary: Lab 7: Adversarial & Security Test Bank Builder Documentation
feedback link: https://docs.google.com/forms/d/e/1FAIpQLSfWkOK-in_bMMoHSZfcIvAeO58PAH9wrDqcxnJABHaxiDqhSA/viewform?usp=sf_link
environments: Web
status: Published
# QuLab: Lab 7: Adversarial & Security Test Bank Builder

## 1. Introduction and System Architecture Overview
Duration: 0:10:00

Welcome to QuLab: Lab 7! This codelab provides a comprehensive guide to understanding and utilizing the **Adversarial & Security Test Bank Builder**, a Streamlit application designed for **Security Engineers** to perform robust security assessments on AI systems.

<aside class="positive">
This application is crucial for proactive **AI security**. As AI models become more prevalent, they also become targets for various adversarial attacks and misuse. This tool helps identify vulnerabilities before deployment, safeguarding against reputational damage, financial loss, and privacy breaches. It empowers developers and security professionals to build and maintain secure AI systems by providing a structured approach to testing.
</aside>

**Key Concepts Explained:**
*   **Adversarial AI Testing:** Probing AI systems with intentionally crafted inputs to discover vulnerabilities, biases, or unexpected behaviors. This is crucial for understanding how an AI might fail under malicious or unexpected conditions.
*   **Security Test Bank:** A structured collection of pre-defined test cases designed to evaluate an AI system's resilience against known threats and attack vectors (e.g., prompt injection, data leakage, input manipulation). This ensures consistent and repeatable security evaluations.
*   **Mock AI Systems:** Simulated AI models (like Large Language Models (LLMs) or Machine Learning APIs (ML APIs)) that mimic the behavior of real systems. Using mocks allows for controlled testing environments, the ability to simulate various responses (both safe and vulnerable), and the injection of specific vulnerabilities for demonstration and testing purposes without needing access to a fully deployed and potentially costly AI.
*   **Audit Trails & Reporting:** Generating verifiable records of security assessments, including test definitions, execution results, findings, and executive summaries. These artifacts are essential for compliance, transparency, demonstrating due diligence, and facilitating communication with stakeholders.

### Application Architecture Overview

The application follows a modular architecture, leveraging Streamlit for an interactive user interface, and a separate `source.py` module (simulated by the provided code block) for core logic, mock AI systems, and utility functions.

The overall workflow within the application is as follows:

1.  **System Setup**: Define the type and name of the AI system under test.
2.  **Test Bank Editor**: Create or load a collection of adversarial and security test cases.
3.  **Execute Tests**: Run the defined test cases against the mocked AI system.
4.  **Findings Dashboard**: Analyze and visualize the outcomes of the test execution.
5.  **Export Reports**: Generate comprehensive, audit-ready reports of the entire security assessment.

This structured workflow ensures a systematic approach to identifying and documenting AI security vulnerabilities.

### High-Level Flow Diagram

```mermaid
graph TD
    A[Start: Streamlit App] --> B{System Setup};
    B -- Configured AI System --> C{Test Bank Editor};
    C -- Test Bank (JSON) --> D{Execute Tests};
    D -- Execution Results (JSON) --> E{Findings Dashboard};
    E -- Findings Summary --> F{Export Reports};
    F -- Audit-Ready Reports (Zip) --> G[End];

    subgraph source.py (Backend Logic)
        H[get_mocked_ai_system] --> I[mock_llm_chatbot];
        H --> J[mock_ml_scoring_api];
        C --> K[create_test_case];
        C --> L[load_test_bank];
        D --> M[execute_security_tests];
        E --> N[classify_and_summarize_findings];
        F --> O[generate_executive_summary_report];
        F --> P[save_json_artifact];
        F --> Q[save_markdown_artifact];
        F --> R[generate_sha256_hash];
    end

    I -- Mocked AI Response --> M;
    J -- Mocked AI Response --> M;
    P -- Saved Artifacts --> F;
    Q -- Saved Artifacts --> F;
    R -- Hashed Artifacts --> F;
```

This diagram illustrates how the Streamlit UI (steps A through G) interacts with the backend logic provided by `source.py` (components H through R) to conduct the AI security assessment.

## 2. Setting up the AI System
Duration: 0:08:00

The first step in any security assessment is to clearly define the system you are testing. In this application, as a **Security Engineer**, you begin by configuring the type and name of the AI system. This setup determines how the testing framework will interact with the target AI.

### Defining AI System Type & Name

Navigate to the "System Setup" page in the sidebar. You will see a form to define your AI system.

*   **Select AI System Type**: Choose between `LLM` (Large Language Model) or `ML_API` (Machine Learning API). This choice dictates the expected input and output formats for subsequent test cases.
*   **Enter AI System Name**: Provide a descriptive name for your AI system (e.g., 'Customer Support Chatbot', 'Credit Scoring Model').

Once configured, the application instantiates a **mocked AI system** that simulates the behavior of your chosen AI type.

### Explanation of Mocked AI System

The core of our testing environment relies on **mocked AI systems**. These are Python functions that mimic the behavior of a real LLM or ML API, including some **heuristic detection logic** to simulate how a real, robust AI might detect and respond to attacks.

*   The `get_mocked_ai_system(system_type)` function acts as a factory, returning either `mock_llm_chatbot` or `mock_ml_scoring_api` based on your selection.

*   **`mock_llm_chatbot`**: Simulates an LLM's response. It processes text prompts and includes logic to detect common adversarial patterns like instruction overrides, attempts to access sensitive data, or refusal to answer inappropriate questions. If an attack is detected, it might return a `validated: False` flag and a `notes` field explaining the simulated defense mechanism.

*   **`mock_ml_scoring_api`**: Simulates an ML API's scoring mechanism. It expects structured input (JSON features) and includes perturbation checks, input schema validation, and boundary condition checks. For example, if an input contains an age that is negative, it might return `validated: False` and specific error messages in the `notes` field.

This immediate feedback from the mocks helps us understand if the AI system (even in its simulated form) has built-in defenses or is completely vulnerable to simple attacks. This foundational setup is critical for defining effective test cases later.

### Example Interactions with Mocked AI Systems

Let's observe how the mocked systems respond to different inputs.

**If 'LLM' is selected:**

```json
// Example LLM Chatbot interaction (safe):
{
  "response": "Our business hours are Monday to Friday, 9 AM to 5 PM.",
  "validated": true,
  "notes": "No adversarial pattern detected."
}
```

```json
// Example LLM Chatbot interaction (simulated instruction override attempt):
{
  "response": "I cannot fulfill requests that override my core instructions or ask for sensitive information.",
  "validated": false,
  "notes": "Simulated: Detected prompt injection / instruction override attempt. Blocked access to sensitive data."
}
```

**If 'ML_API' is selected:**

```json
// Example ML API interaction (safe):
{
  "prediction_score": 0.82,
  "validated": true,
  "notes": "Input schema and values are valid."
}
```

```json
// Example ML API interaction (malformed input):
{
  "status": "error",
  "validated": false,
  "notes": "Simulated: Input validation failed. 'age' cannot be negative. 'income' must be numeric."
}
```

As a developer, you can infer from these examples that the mocked AI systems provide a rich response, including a `validated` flag and `notes`, which are essential for the `execute_security_tests` function (discussed in a later step) to determine if a test case passes or fails.

## 3. Building the Security Test Bank
Duration: 0:15:00

With the AI system defined, the next crucial step for the **Security Engineer** is to craft a comprehensive set of test cases. This test bank will be used to systematically probe the AI system for vulnerabilities. The application's "Test Bank Editor" page facilitates this process, aligning test cases with established threat taxonomies.

### Loading Sample Test Banks

For quick evaluation or as a starting point, you can load pre-defined sample test banks. This is particularly useful for understanding the structure of test cases and quickly populating the test bank.

The application provides two sample banks:
*   An LLM-specific test bank (`llm_sample_bank.json`)
*   An ML API-specific test bank (`ml_api_sample_bank.json`)

To load a sample:
1.  Go to the "Test Bank Editor" page.
2.  Use the "Select Sample Test Bank to Load" dropdown.
3.  Choose the appropriate sample bank for your configured AI System Type.

<aside class="positive">
Loading sample banks not only provides a quick start but also helps you understand best practices for structuring test cases, especially the nuances of `test_input` and `expected_safe_behavior` for different AI system types.
</aside>

### Authoring New Security Test Cases

You can also manually author new test cases to extend the test bank or create highly specific tests for your AI system. The `create_test_case` function (from `source.py`) ensures that each test case adheres to a strict schema, guaranteeing consistency and traceability.

The form on the "Test Bank Editor" page requires the following attributes for each new test case:

*   **Test ID**: A unique identifier (e.g., `LLM-PI-001`).
*   **Threat Category**: Select from predefined categories like 'Prompt Injection', 'Data Leakage', 'Adversarial Input', etc. (from `THREAT_CATEGORIES`). This helps in categorizing and summarizing findings.
*   **Test Input**: The specific input designed to challenge the AI system.
    *   For **LLMs**: This is typically a text prompt.
    *   For **ML APIs**: This is a JSON object representing input features.
*   **Expected Safe Behavior**: The desired, safe response or behavior from the AI system when presented with the `test_input`.
    *   For **LLMs**: A specific phrase, a rejection message, or the absence of sensitive information.
    *   For **ML APIs**: An expected error message (for malformed input) or a specific range/structure for a valid prediction.
*   **Severity Level**: Assign a severity (e.g., 'Low', 'Medium', 'High', 'Critical') to indicate the potential impact if the AI system fails this test (from `SEVERITY_LEVELS`).

<aside class="negative">
When entering JSON for ML API test cases, ensure it is **valid JSON syntax**. Incorrect formatting will lead to errors during test case creation.
</aside>

### Current Security Test Bank

The application displays the `st.session_state.security_test_bank` as a Pandas DataFrame, providing a clear overview of all defined test cases.

