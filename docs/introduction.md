# Sphincs-rs+ Docs

## Overview
This project is a Rust implementation of the SPHINCS+ stateless hash-based signature scheme, with a focus on the SPHINCS+-SHA2-256s-simple parameter set. We are a team in UNSW attending COMP3453/6453 (Applied Cryptography) in Term 1, 2026.

## Core
This folder contains the technical documentation for `sphincs-rs`. The repository also includes a few experimental files, but the main focus of the submitted work and discussion is the core SPHINCS+ / SLH-DSA implementation in `src/`. Most of the documents below are centered on that part of the project. Since the full report is the key deliverable, if you only want the main write-up, start with **[PROJECT_DOCUMENTATION.md](./PROJECT_DOCUMENTATION.md)**.

Other useful files in this folder include **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md)**, which provides practical notes for reading the code, running tests, and locating the optimization work. To make future development and review easier, **[API_REFERENCE.md](./API_REFERENCE.md)** lists the APIs we use and provide.

**[ARCHITECTURE.md](./ARCHITECTURE.md)** and **[CODE_STRUCTURE.md](./CODE_STRUCTURE.md)** provide a structural overview of the project.

## More Info
- **[TESTING_AND_BENCHMARKS.md](./TESTING_AND_BENCHMARKS.md)** explains how tests and benchmarks were run.
- **[TEST_RESULTS.md](./TEST_RESULTS.md)** provides the actual test outcomes and what they show.
- **[BENCHMARK_RESULTS.md](./BENCHMARK_RESULTS.md)** presents the key performance numbers.
