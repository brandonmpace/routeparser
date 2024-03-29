import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="routeparser",
    version="0.1.0",
    author="Brandon M. Pace",
    author_email="brandonmpace@gmail.com",
    description="A route command output text parser",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    keywords="network route parser",
    license="GNU Lesser General Public License v3 or later",
    platforms=['any'],
    python_requires=">=3.6.5",
    url="https://github.com/brandonmpace/routeparser",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3"
    ]
)
