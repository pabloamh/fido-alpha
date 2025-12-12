"""Setup installer for Fido."""

import re
from pathlib import Path

from setuptools import setup, find_packages


def read(*parts):
    """Read the contents of files in parts and return contents."""
    return Path(Path(__file__).parent, *parts).read_text(encoding='utf-8')


def find_version(*file_paths):
    """Search contents of files in file_paths for version number."""
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


install_requires = [
    'olefile >= 0.46, < 1',
    'importlib-resources; python_version < "3.7"',
    'requests',
    'aiohttp',
    'aiofiles',
    'aiopath',
]


setup_requires = [
    'pytest-runner',
]


tests_require = [
    'pytest', 'flake8', 'pep257', 'pytest-cov', 'pylint'
]

EXTRAS = {
    'testing': tests_require,
    'setup': setup_requires,
}

setup(
    name='opf-fido',
    version=find_version('fido', '__init__.py'),
    description='Format Identification for Digital Objects (FIDO).',
    long_description='A command-line tool to identify the file formats of digital objects. FIDO uses the UK National Archives (TNA) PRONOM File Format and Container descriptions.',
    author='Adam Farquhar (BL), 2010',
    url='http://openpreservation.org/technology/products/fido/',
    license='Apache License 2.0',
    install_requires=install_requires,
    python_requires='>=3.6',
    setup_requires=setup_requires,
    tests_require=tests_require,
    extras_require=EXTRAS,
    packages=find_packages(),
    package_data={'fido': ['*.*', 'conf/*.*', 'signatures/*.*', 'pronom/*.*']},
    entry_points={'console_scripts': [ 
        'fido = fido.cli:main',
        'fido-prepare = fido.prepare:main',
        'fido-update-signatures = fido.update_signatures:main',
        'fido-toxml = fido.toxml:main',
    ]},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ]
)
