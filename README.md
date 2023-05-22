# Phantom 

This repository contains a PHP vulnerability scanner, a tool designed by **Chat-GPT**  to identify security vulnerabilities in PHP applications. The scanner uses utilized various regexto detect common security weaknesses and potential exploits in PHP code.
![Alt text](https://github.com/0xBugatti/Phantom/blob/f7580bcf55dcbe6a1d24dc99d0ce4948fb6e9944/phantom.png "Photo")
## Features

-   **Static Analysis**: The scanner performs static analysis on PHP source code to identify potential vulnerabilities. It analyzes the code structure, variable usage, function calls, and other patterns to detect security flaws.
-   **Vulnerability Detection**: The scanner incorporates a set of predefined rules and checks to identify common vulnerabilities such as SQL injection, cross-site scripting (XSS), remote code execution, file inclusion, and more.
      - Detected Vulnerabilities
        - XSS
        - SQL Injection
        - OS Command Injection
        - LFI
        - Unristricted File Upload (Potential)
        - SSRF (Under Development)
-   **WEB-UI**: open the tool web page throgh `http://127.0.0.1:5000` and start Upload your Php File.     
        
-   **Extensibility**: The tool allows for easy extensibility by providing an API that allows developers to create custom vulnerability checks and add them to the scanning process.
-   **Dashbiard Reporting**: After scanning a PHP application, the scanner generates a detailed report highlighting the identified vulnerabilities, including their severity, affected code snippets, and recommendations for remediation.

## Requirements

-   Python 
-   flask

## Installation

1.  Clone the repository:
    
    bashCopy code
    
    `git clone https://github.com/your-username/php-vulnerability-scanner.git`
    
2.  Change to the project directory:
    
    bashCopy code
    
    ```bash
cd php-vulnerability-scanner```
    
3.  Install the dependencies using Composer:
    
    bashCopy code
    
    `composer install`
    

## Usage

1.  Navigate to the project directory.
    
2.  Run the vulnerability scanner command, providing the path to the PHP application you want to scan:
    
    bashCopy code
    
    `php scanner.php /path/to/php/application`
    
    Replace `/path/to/php/application` with the actual path to your PHP application.
    
3.  Wait for the scanner to analyze the code and generate the report.
    
4.  Once the scanning process is complete, the tool will generate a report file containing information about the identified vulnerabilities.
    

## Extending the Scanner

The scanner can be extended by creating custom vulnerability checks. To add a custom check, follow these steps:

1.  Create a new PHP class that extends the `VulnerabilityCheck` class.
    
2.  Implement the `check()` method, which performs the necessary analysis to identify the vulnerability.
    
3.  Register the new check with the scanner by adding an instance of your custom class to the `$checks` array in the `scanner.php` file.
    
4.  Re-run the scanner to include the custom check in the scanning process.
    

## Contributing

Contributions to this project are welcome! If you encounter any issues or have ideas for improvements, please open an issue or submit a pull request on the GitHub repository.

When contributing, please ensure you follow the existing coding style and include appropriate tests for any new features or bug fixes.

## License

This project is licensed under the [MIT License](https://chat.openai.com/LICENSE). Feel free to use, modify, and distribute this code for both commercial and non-commercial purposes.
