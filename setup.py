"""
Setup.py for superset-patchup
"""
from setuptools import setup, find_packages

setup(
    name='superset-patchup',
    version=__import__('superset_patchup').__version__,
    description='Superset blueprint for Canopy - https://canopyinsights.com',
    license='Apache2',
    author='Ona Systems Inc',
    author_email='superset-patchup+tech@ona.io',
    url='https://github.com/onaio/superset-patchup',
    packages=find_packages(exclude=['docs', 'tests']),
    install_requires=[
        'Superset',
    ],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ],
)
