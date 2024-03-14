import setuptools
from setuptools import setup, find_packages

requires = [
    'six==1.15.0',
    'PyYAML~=5.3.1',
    'setuptools~=50.3.2',
    'lxml>=4.6',
    'bitarray'
]

with open("README.md", "r", encoding="utf-8") as fh:
    readme = fh.read()

setup(
    name='xtce_generator',
    version='1.2.4',
    url='https://github.com/WindhoverLabs/xtce_generator',
    license='3BSD-3-Clause',
    author='Lorenzo Gomez',
    author_email='lgomez@windhoverlabs.com',
    description='A tool to generate xtce files from a sqlite database. ',
    long_description=readme,
    long_description_content_type='text/markdown',
    install_requires=requires,
    packages=setuptools.find_namespace_packages(where="src"),
    package_dir={'':'src'},
    python_requires='>=3.6.0',
#   FIXME:Add entry_points
)
