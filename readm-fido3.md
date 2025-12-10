# Format Identification for Digital Objects (FIDO)

FIDO is a project of the [Open Preservation Foundation](http://www.openpreservation.org).

[![Build Status](https://travis-ci.org/openpreserve/fido.svg?branch=master)](https://travis-ci.org/openpreserve/fido) [![Code Coverage](https://codecov.io/gh/openpreserve/fido/branch/master/graph/badge.svg)](https://codecov.io/gh/openpreserve/fido)

FIDO is a Python library and command-line tool for identifying the file formats of digital objects. It is designed for simple integration into digital preservation workflows and other applications requiring reliable format identification.

This document provides an overview of FIDO's structure, installation, and usage, both as a standalone application and as a library integrated into other Python projects.

## Project Structure

The FIDO project has been refactored to follow modern, object-oriented design principles, making it more modular and easier to maintain and extend.

The key components of the project are:

*   **`fido/fido.py`**: The main application class and command-line entry point. It orchestrates the format identification process.
*   **`fido/models.py`**: Contains the data classes (`FileFormat`, `Signature`, `Pattern`) that represent the core data structures.
*   **`fido/package.py`**: Handles the loading and parsing of format signatures, as well as the logic for identifying files within containers like ZIP and TAR archives.
*   **`fido/config.py`**: Centralized configuration for default settings, such as buffer sizes and output formats.
*   **`fido/pronom/`**: A package for interacting with the PRONOM technical registry, including downloading new signature files.

This structure separates concerns, making the codebase cleaner and more approachable for new developers.

## Installation

FIDO can be installed on any platform with Python 3.6+ and `pip`.

### Using pip

The recommended way to install FIDO is via `pip`:

```shell
pip install opf-fido
```

This will install FIDO and its dependencies. On Linux/macOS, you may need to use `sudo`:

```shell
sudo pip install opf-fido
```

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
    for file_format, signature_name in matches:
        print(f"  - PUID: {file_format.puid}")
        print(f"    Name: {file_format.name}")
        print(f"    Version: {file_format.version or 'N/A'}")
        print(f"    MIME Type: {file_format.mime or 'N/A'}")
        print(f"    Matching Signature: {signature_name}")
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