from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="phantomeye",
    version="1.0.0",
    author="Aman Kumar Panda",
    author_email="amanpanda987@gmail.com",
    description="AI-Powered OSINT Intelligence Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AmanPanda24/phantomeye",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "phantomeye=phantomeye.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
        "Development Status :: 4 - Beta",
    ],
    keywords="osint reconnaissance security intelligence kali linux",
)
