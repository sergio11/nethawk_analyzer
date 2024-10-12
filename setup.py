from setuptools import setup, find_packages

setup(
    name='NetHawkAnalyzer',  
    version='0.1.10',
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
        'fpdf2==2.8.1'
    ],
    author='Sergio Sánchez Sánchez',
    author_email='dreamsoftware92@gmail.com',
    description='🔍💻 NetHawkAnalyzer: An advanced AI-powered tool for ethical hacking, cybersecurity network analysis, and vulnerability assessment. 🦅✨',
    keywords=['cybersecurity', 'ethical hacking', 'network analysis', 'vulnerability assessment', 'AI', 'Scapy', 'Nmap', 'Python', 'information security', 'security auditing'],
    url='https://github.com/sergio11/nethawk_analyzer',
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