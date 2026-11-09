import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="quicksand",
    version="2.2.0",
    author="tylabs.com",
    author_email="nospam@tylabs.com",
    description="QuickSand is a module to scan streams inside documents with Yara",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tylabs/quicksand",
    download_url="https://github.com/tylabs/quicksand/archive/refs/tags/2.2.0.tar.gz",
    include_package_data=True,
    package_data={
        "quicksand": ["*.yara"],
    },
    keywords=['document', 'malware', 'forensics', 'yara', 'parser'],
    project_urls={
        "Bug Tracker": "https://github.com/tylabs/quicksand/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=['quicksand'],
    entry_points={
        "console_scripts": [
            "quicksand=quicksand:main",
        ],
    },
    python_requires=">=3.7",
    install_requires=[
        'yara-python>=4.3.0',
    ],
)
