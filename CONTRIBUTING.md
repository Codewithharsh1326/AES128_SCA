# Contributing to AES128_SCA

First off, thank you for considering contributing to this hardware security and side-channel analysis project! 

## How to Contribute

Whether you are improving the Verilog RTL, optimizing the machine learning extraction scripts, or just fixing typos in the documentation, all contributions are welcome.

### Contribution Steps:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-amazing-feature`).
3. Make your changes.
4. If you modify the RTL, please run the testbench (`aes_tb.v`) to ensure the AES-128 core still produces the correct NIST test vectors.
5. Commit your changes (`git commit -m 'feat: add some amazing feature'`).
6. Push to the branch (`git push origin feature/your-amazing-feature`).
7. Open a Pull Request.

## Development Environment Setup
- **Hardware Simulation:** Ensure you have `iverilog` installed.
- **Machine Learning:** We recommend using Python 3.12. Install the required packages using `pip install -r requirements.txt`.
