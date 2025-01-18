from setuptools import setup, find_packages

setup(
    name="ghostshell",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "psutil",
        "pythonping",
        "scapy",
        "PySide6",
        "argparse",
    ],
    entry_points={
        "console_scripts": [
            "ghostshell=ghostshell:main",
        ],
    },
)
