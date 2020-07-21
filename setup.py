# cryptonice
# setup.py

import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="cryptonice",
    version="0.1.16",
    description="Perform TLS scan of single domain",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/F5-Labs/cryptonice",
    author="Katie Newbold",
    author_email="katiesnewbold@gmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    packages=["cryptonice"],
    include_package_data=True,
    install_requires=["sslyze>=3.0.0",
                      "cryptography>=2.6",
                      "nassl>=3.0.0",
                      "dnspython>=1.16.0",
                      "http-client>=0.1.21",
                      "tls-parser>=1.2.1",
                      "urllib3>=1.25.9",
                      "ipaddress>=1.0.22"
                      "pathlib~=1.0.1",
                      "pycurl~=7.43.0.5"],
    entry_points={
        "console_scripts": [
            "cryptonice=cryptonice.__main__:main",
        ]
    },
)
#
