from setuptools import setup, find_packages

setup(
    name='NetHawk',  
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'scapy==2.6.0',
        'tqdm==4.65.0',
        'rich==13.9.2',
        'pysmb==1.2.10',
        'python3-nmap==1.9.1',
        'langchain==0.2.16',
        'langchain-groq==0.1.10',
        'fpdf2==2.8.1',
        'python-dotenv==1.0.1'
    ],
    author='Sergio Sánchez Sánchez',
    author_email='dreamsoftware92@gmail.com',
    description='A package for cybersecurity network analysis and vulnerability assessment.',
    url='https://github.com/tu_usuario/nethawk',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    python_requires='>=3.7, <4',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown'
)