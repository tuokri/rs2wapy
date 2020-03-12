import setuptools

import versioneer

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="rs2wapy",
    version=versioneer.get_version(),
    packages=setuptools.find_packages(),
    package_dir={"rs2wapy": "rs2wapy"},
    url="https://github.com/tuokri/rs2wapy",
    author="tuokri",
    author_email="tuokri@tuta.io",
    description="Rising Storm 2: Vietnam WebAdmin Python Interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="automation webadmin ue3 rcon",
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    cmdclass=versioneer.get_cmdclass(),
    python_requires=">=3.7",
    install_requires=[
        "beautifulsoup4",
        "bs4",
        "Logbook",
        "pycurl",
        "soupsieve",
        "requests",
        "steam",
        "regex",
    ]
)
