from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

with open('VERSION') as f:
    version = f.read()

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='winagent',
    version=version,
    description='Tactical RMM Windows Agent',
    long_description=readme,
    author='wh1te909',
    url='https://github.com/wh1te909/winagent',
    license=license,
    install_requires=requirements,
    packages=find_packages(exclude=('tests', 'docs'))
)