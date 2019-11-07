import setuptools

setuptools.setup(
    name="rs2wapy",
    version="0.1.9",
    packages=setuptools.find_packages(),
    url="https://github.com/tuokri/rs2wapy",
    author="tuokri",
    author_email="tuokri@tuta.io",
    description="Rising Storm 2: Vietnam WebAdmin Python Interface",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "beautifulsoup4>=4.8.1",
        "bs4>=0.0.1",
        "Logbook>=1.5.3",
        "pycurl>=7.43.0.3",
        "soupsieve>=1.9.5",
    ]
)
