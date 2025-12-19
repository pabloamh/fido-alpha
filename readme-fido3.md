# FIDO - Format Identification for Digital Objects

FIDO is a modern, object-oriented Python 3 library and command-line tool for identifying the file formats of digital objects. It is designed for simple integration into automated workflows and other applications requiring reliable format identification.

This version of FIDO is a complete refactoring of the original Python 2 tool, focusing on code clarity, maintainability, and modern Python practices, including extensive use of `asyncio` for high-performance I/O operations.

## Key Features

The FIDO project has been refactored to follow modern, object-oriented design principles, making it more modular and easier to maintain and extend. Key features include:

*   **Modern Python 3 Codebase**: Fully migrated from Python 2, removing legacy dependencies like `six` and `futures`.
*   **Asynchronous I/O**: Utilizes `asyncio` and `aiopath` for high-performance, concurrent file identification, making it ideal for large-scale processing.
*   **Object-Oriented Design**: A clean, class-based architecture that separates concerns and improves code readability.
*   **Container Support**: Identifies formats within container files like ZIP, TAR, and OLE archives.
*   **PRONOM-Based**: Uses the latest format signatures from The UK National Archives' PRONOM technical registry.
*   **Flexible Usage**: Can be used as a command-line tool or as a library integrated into other Python applications.

## Project Structure
*   **`fido/fido.py`**: The main `Fido` class and command-line entry point.
*   **`fido/loader.py`**: Handles loading and parsing of PRONOM XML signature files.
*   **`fido/package.py`**: Logic for handling various container and archive formats (ZIP, TAR, OLE, etc.).
*   **`fido/pronom.py`**: A package for interacting with the PRONOM registry to update signatures.

## Installation

FIDO can be installed on any platform with Python 3.9+ (required for full async support) and `pip`. It is recommended to install it within a virtual environment.

1.  Clone the repository from GitHub:
    ```shell
    git clone https://github.com/your-username/fido-alpha.git
    cd fido-alpha
    ```
2.  Install FIDO and its dependencies. For development, it's recommended to install in editable mode:
    ```shell
    pip install -e .
    ```
    This will install the package, and any changes you make to the source code will be immediately effective.
    For production use, you can install it with `pip install .`.

Once installed, you can verify the installation by running:

```shell
fido -h
```

### Manual Installation

1.  Download the latest zip release from <https://github.com/openpreserve/fido/releases>.
2.  Unzip the archive into a directory of your choice.
3.  Navigate to the directory in your command shell.
4.  Run the following command to install FIDO:

    ```shell
    python setup.py install
    ```

## Usage

FIDO can be used both as a command-line tool and as a library within your own Python applications.

### As a Command-Line Application

The command-line interface allows you to identify files directly from your shell.

```shell
usage: fido [-h] [-v] [-q] [-recurse] [-zip] [-noextension] [-nocontainer]
            [-pronom_only] [-input INPUT] [-filename FILENAME]
            [-useformats INCLUDEPUIDS] [-nouseformats EXCLUDEPUIDS]
            [-matchprintf FORMATSTRING] [-nomatchprintf FORMATSTRING]
            [-bufsize BUFSIZE] [-sigs SIG_ACT]
            [-container_bufsize CONTAINER_BUFSIZE]
            [-loadformats XML1,...,XMLn] [-confdir CONFDIR]
            [FILE [FILE ...]]
```

**Examples:**

*   Identify all files in the current directory and its subdirectories, saving the output to `file-info.csv`:

    ```shell
    fido -recurse . > file-info.csv
    ```

*   Identify files from a list, including the contents of ZIP and TAR archives:

    ```shell
    fido -input files.txt -zip
    ```

*   Identify a file from standard input:

    ```shell
    cat myfile.txt | fido -
    ```

### As a Library

The refactored FIDO library provides a clean, object-oriented API for integration into your Python projects.

Here is an example of how to use the `Fido` class to identify a file:

```python
from fido import Fido

# Initialize FIDO. It will load the default signatures.
fido_instance = Fido()

# Path to the file you want to identify
file_to_identify = "path/to/your/file.pdf"

# Identify the file
matches = fido_instance.identify_file(file_to_identify)

# Process the results
if matches:
    print(f"Found {len(matches)} match(es) for {file_to_identify}:")
    for match in matches:
        print(f"  - PUID: {match['puid']}")
        print(f"    Name: {match['name']}")
        print(f"    Version: {match['format'].version or 'N/A'}")
        print(f"    MIME Type: {match['format'].mime or 'N/A'}")
        print(f"    Matching Signature: {match['signature_name']}")
else:
    print(f"No format match found for {file_to_identify}.")

```

The `identify_file` method returns a list of tuples, where each tuple contains a `FileFormat` data class instance and the name of the signature that matched.

## Updating Signatures

FIDO uses signatures from the PRONOM technical registry to identify file formats. You can update these signatures using the command line.

*   **Check for new signature versions:**

    ```shell
    fido -sigs check
    ```

*   **Update to the latest signature version:**

    ```shell
    fido -sigs update
    ```

*   **List all available signature versions:**

    ```shell
    fido -sigs list
    ```

## Dependencies

FIDO requires Python 3.6+ and the following Python packages:

*   `olefile`
*   `requests`

These dependencies are installed automatically when you install FIDO using `pip` or `setup.py`.