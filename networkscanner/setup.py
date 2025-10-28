from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="network-scanner",
    version="1.0.0",
    author="EmreCyberX",
    author_email="your.email@example.com",
    description="Gelişmiş ağ tarama aracı",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/EmreCyberX/network-scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "network-scanner=src.__main__:main",
        ],
    },
)