# Test Maven Project with Vulnerable Dependencies

⚠️ **WARNING: This project contains intentionally vulnerable dependencies for testing purposes only. DO NOT use in production!**

## Purpose

This is a test project for the Snoop security audit tool. It contains a `pom.xml` file with multiple vulnerable Maven dependencies to test the tool's ability to detect known security vulnerabilities in Java projects.

## Vulnerable Dependencies

This project includes the following intentionally vulnerable dependencies:

1. **Log4j 2.14.1** - Contains the critical Log4Shell vulnerability (CVE-2021-44228)
2. **Jackson Databind 2.9.8** - Multiple known deserialization vulnerabilities
3. **Spring Framework 5.2.0.RELEASE** - Known security vulnerabilities
4. **Apache Commons Text 1.6** - CVE-2022-42889 vulnerability
5. **Apache Struts 2.5.20** - Multiple known vulnerabilities
6. **Netty 4.1.42.Final** - Known security issues
7. **H2 Database 1.4.199** - Known vulnerabilities
8. **Snakeyaml 1.26** - Known deserialization vulnerabilities

## Usage

Run Snoop from the parent directory:

```bash
cd /Users/brandonapol/code/snoop
./snoop --path test-project-maven --verbose
```

## Expected Results

Snoop should detect multiple high and critical severity vulnerabilities in this project using the OSV (Open Source Vulnerabilities) API.

## Cleanup

This project is for testing only. The dependencies are never installed, only the `pom.xml` file is scanned.
