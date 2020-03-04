import setuptools

import versioneer

setuptools.setup(
    name="rs2wapy",
    version=versioneer.get_version(),
    packages=["rs2wapy"],
    url="https://github.com/tuokri/rs2wapy",
    author="tuokri",
    author_email="tuokri@tuta.io",
    description="Rising Storm 2: Vietnam WebAdmin Python Interface",
    keywords="automation webadmin ue3",
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    install_requires=[
        "beautifulsoup4",
        "bs4",
        "Logbook",
        "pycurl",
        "soupsieve",
        "requests",
        "steam",
    ]
)
