from setuptools import find_packages, setup

setup(
    packages=find_packages(include=["guard_core", "guard_core.*"]),
    include_package_data=True,
    package_data={
        "guard_core": ["py.typed"],
    },
)
