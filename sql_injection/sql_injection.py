import subprocess

def run_sqlmap(url):
    """
    Runs SQLmap on the given URL to test for SQL Injection vulnerabilities.

    Args:
        url (str): The URL to test for SQL Injection.

    Returns:
        str: Path to the results file or an error message.
    """
    try:
        # Define the path to sqlmap.py
        sqlmap_path = './sqlmap/sqlmap.py'

        # Create the SQLmap command
        command = [
            'python3', sqlmap_path,
            '-u', url,               # The URL to test for SQL Injection
            '--batch',               # Automatically proceed with default options
            '--level=5',             # Maximum level of testing
            '--risk=3',              # Maximum risk for more aggressive tests
            '--threads=10'           # Use 10 threads for faster testing
        ]

        # Run the SQLmap command
        result = subprocess.run(command, capture_output=True, text=True)

        # Define the output file path
        output_file = "./sqlmap_result.txt"

        # Save the results to a file
        with open(output_file, "w") as file:
            if result.returncode == 0:
                file.write(result.stdout)
            else:
                file.write(f"Error: {result.stderr}")

        # Return the file path for downloading
        return output_file
    except Exception as e:
        error_file = "./sqlmap_error.txt"
        with open(error_file, "w") as file:
            file.write(f"Error running SQLmap: {str(e)}")
        return error_file
