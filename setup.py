from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read()
    setup(
        name="openapi_elm_function_generator",
        version="0.1.0",
        author="Farooq Azam Khan",
        author_email="khanazamfarooq99@gmail.com",
        license="MIT Lisence",
        description="fastapi has a /openapi.json file that can be used to generate functions for the frontend SPA.",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/Farooq-azam-khan/elm-api-functions-code-gen",
        py_modules=["get_all_routes"],
        packages=find_packages(),
        install_requires=[requirements],
        python_requires=">=3.12",
        classifiers=[
            "Programming Language :: Python :: 3.8",
            "Operating System :: OS Independent",
        ],
        entry_points="""
        [console_scripts]
        elm_openapi_codegen=get_all_routes:main
    """,
    )
