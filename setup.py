from setuptools import setup, find_packages

setup(
    name='iguana',
    version='0.1.0',
    description='A network scanning tool for Kali Linux',
    long_description=open('README.md').read(),
    author='Uveis Smajli',
    author_email='smajliuveis@yahoo.com',
    url='https://github.com/uveissmjl/iguana',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'iguana=network_scanner.iguana:main',
        ],
    },
    install_requires=[
        'scapy',
        'dnspython',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
