from setuptools import setup, find_packages

setup(
    name='iguana',
    version='0.1.0',
    description='A network scanning tool for Kali Linux',
    long_description=open('README.md').read(),
    long_description_content_type='Iguana is an open-source, Python-based tool designed for network enthusiasts, cybersecurity students, and professionals looking to perform comprehensive network analyses. It integrates a variety of functionalities into one convenient suite, enabling users to inspect and audit networks efficiently. With Iguana, you can perform network scanning to discover active devices, conduct port scanning to identify open ports, capture and analyze network traffic, and gather DNS information for domain reconnaissance.',
    author='Uveis Smajli',
    author_email='smajliuveis@yahoo.com',
    url='https://github.com/uveissmjl/iguana',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'iguana=iguana.py:main',
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
