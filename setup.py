from setuptools import setup, find_packages

setup(
    name="styx-sdk",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "xrpl-py>=4.0.0",
        "cryptography>=42.0.0",
        "pynacl>=1.5.0",
    ],
    python_requires=">=3.10",
    author="Sentinel Intelligence LLC",
    description="Styx Protocol SDK — End-to-End Encrypted Communication over XRPL",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
