from setuptools import setup

setup(
    name='aws-check-publicly-exposed',
    version='1.0',
    description='Check your EC2 and ELB public exposure',
    license='Apache2',
    url='https://github.com/trackit/aws-check-publicly-exposed',
    scripts=['check_aws_publicly_exposed.py'],
    py_modules=['check_aws_publicly_exposed'],
    install_requires=[
        'boto3',
    ],
    entry_points={
        'console_scripts': [
            'check-aws-publicly-exposed=check_aws_publicly_exposed:main'
        ]
    }
)
