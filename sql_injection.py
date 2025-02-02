import subprocess
import gradio as gr

def install_sqlmap():
    """Install SQLMap by cloning the repository if it's not already cloned."""
    try:
        # Install git if necessary
        subprocess.run(['apt-get', 'install', 'git', '-y'], check=True)

        # Clone the SQLmap repository if it's not already cloned
        subprocess.run(['git', 'clone', '--recursive', 'https://github.com/sqlmapproject/sqlmap.git'], check=True)

        return "SQLMap installed successfully!"
    except subprocess.CalledProcessError as e:
        return f"Error installing SQLMap: {e}"

def run_sqlmap(url):
    try:
        # Path to the sqlmap script
        sqlmap_path = '/content/sqlmap/sqlmap.py'  # Adjust path based on your environment

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
        output_file = "/content/sqlmap_result.txt"

        # Save the results to a file
        with open(output_file, "w") as file:
            if result.returncode == 0:
                file.write(result.stdout)
            else:
                file.write(f"Error: {result.stderr}")

        return output_file
    except Exception as e:
        error_file = "/content/sqlmap_error.txt"
        with open(error_file, "w") as file:
            file.write(f"Error running SQLmap: {str(e)}")
        return error_file
