# cryptonice
# setup.py

from pathlib import Path
from setuptools import find_packages
import sys
from os import path
from pathlib import Path

# The directory containing this file
HERE = Path(__file__).parent

# Setup file based on cryptonice/setup.py
root_path = Path(__file__).parent.absolute()

# The text of the README file
README = (HERE / "README.md").read_text()

# For cx_freeze builds, we need a special setup() function
if len(sys.argv) > 1 and sys.argv[1] == "build_exe":
    from cx_Freeze import setup
    from cx_Freeze import Executable
else:
    from setuptools import setup

    # Create fake Executable that does nothing so the setup.py file can be used on Linux
    class Executable:  # type: ignore
        def __init__(self, script, targetName):  # type: ignore
            pass


# This call to setup() does all the work
setup(
    name="cryptonice",
    version="1.0.8",
    description="Perform TLS scan of a domain",
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
    python_requires='>=3',
    packages=["cryptonice"],
    include_package_data=True,
    install_requires=["sslyze>=3.0.0",
                      "dnspython>=2.0.0",
                      "http-client>=0.1.21",
                      "urllib3>=1.25.9",
                      "ipaddress>=1.0.22",
                      "pathlib~=1.0.1",
                      "bs4>=0.0.1",
                      "regex>=2020.5.14"],
    entry_points={
        "console_scripts": [
            "cryptonice=cryptonice.__main__:main",
        ]
    },
    # cx_freeze info for executable builds with Python embedded
    options={"build_exe": {"packages": ["sslyze", "urllib3", "dns", "http_client", "ipaddress", "pathlib", "cryptography"],
                           "include_files": ["cryptonice"]}},
    executables=[Executable(path.join("cryptonice", "__main__.py"), targetName="cryptonice.exe")],
)
#
