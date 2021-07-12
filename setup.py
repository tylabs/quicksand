import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="quicksand",
    version="2.0.12",
    author="Tyler McLellan",
    author_email="nospam@tylabs.com",
    description="QuickSand is a module to scan streams inside documents with Yara",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tylabs/quicksand",
    download_url="https://github.com/tylabs/quicksand/archive/refs/tags/2.0.12.tar.gz",
    include_package_data=True,
    keywords = ['document', 'malware', 'forensics', 'yara', 'parser'],
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
    scripts=['bin/quicksand'],
    python_requires=">=3.6",
    install_requires=['pdfreader',
        'oletools',
        'cryptography',
        'zipfile38',
        'msoffcrypto-tool',
        'olefile',
        'yara-python']
)
