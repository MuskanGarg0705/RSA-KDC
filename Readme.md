# RSA-KDC: Scalable Key Distribution Center

## Project Overview
RSA-KDC is a scalable Key Distribution Center (KDC) system designed to establish and manage secure cryptographic keys using RSA encryption and the Extended Euclidean Algorithm.

The project focuses on secure key establishment in Advanced Metering Infrastructure (AMI) smart grid environments, where a large number of smart meters require secure communication and efficient key management.

## Objectives
- Implement RSA-based cryptographic key management.
- Develop a centralized Key Distribution Center (KDC).
- Use the Extended Euclidean Algorithm for calculating modular multiplicative inverses.
- Support secure key establishment between communicating entities.
- Explore scalable key management for smart grid environments.

## Key Features
- RSA key generation and cryptographic operations.
- KDC-based key establishment and distribution.
- Extended Euclidean Algorithm implementation.
- Database integration for key-related data management.
- Simulation of the key establishment process.
- Phase-wise testing of project components.

## Technologies Used
- **Programming Language:** Python
- **Cryptographic Algorithm:** RSA
- **Mathematical Algorithm:** Extended Euclidean Algorithm
- **Database:** As implemented in the project
- **Development Environment:** Python / VS Code

## Project Structure
- `app.py` – Application entry point.
- `database.py` – Database-related operations.
- `extended_euclid.py` – Extended Euclidean Algorithm implementation.
- `kdc.py` – Key Distribution Center implementation.
- `rsa.py` – RSA cryptographic operations.
- `simulator.py` – Simulation of the system.
- `test_phase1.py` to `test_phase5.py` – Phase-wise testing files.

## How It Works
1. RSA cryptographic operations are used for key management.
2. The Extended Euclidean Algorithm supports modular inverse calculations.
3. The KDC manages the key establishment process.
4. The simulator helps demonstrate the system workflow.
5. Test files are used to verify different implementation phases.

## Applications
- Advanced Metering Infrastructure (AMI).
- Smart Grid Communication Systems.
- Secure Key Establishment.
- Centralized Cryptographic Key Management.

## Future Scope
- Improve scalability for large smart meter networks.
- Enhance key management efficiency.
- Extend integration with real-world smart grid communication environments.

## Contributors
Developed as an academic mini-project.

## License
This project is developed for academic and educational purposes.
