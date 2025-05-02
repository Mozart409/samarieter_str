# Samarieter Str

A personal finance app designed to help you take control of your money and achieve your financial goals.

## Table of Contents
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Budgeting Tools**: Create and manage budgets to track your spending.
- **Expense Tracking**: Record and categorize your expenses.
- **Financial Insights**: Gain insights into your spending habits with visualizations.
- **Customizable**: Adapt the app to suit your personal financial needs.
- **Secure**: Built with a focus on privacy and data security.

## Tech Stack
Samarieter Str is built using:
- **Frontend**: HTML, CSS
- **Backend**: Rust
- **Configuration and Build Management**: Nix
- **Scripting**: Shell

## Installation
To get started with Samarieter Str, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/Mozart409/samarieter_str.git
   cd samarieter_str
   ```

2. Set up the environment:
   - Ensure you have [Nix](https://nixos.org/download.html) installed.
   - Run the following command to set up the project:
     ```bash
     nix-shell
     ```

3. Build the project:
   ```bash
   cargo build --release
   ```

4. Run the app:
   ```bash
   ./target/release/samarieter_str
   ```

## Usage
Once the app is running, you can:
- Set up your budget categories.
- Add and view expense records.
- Analyze your financial data.

Feel free to modify the app according to your personal requirements.

## Contributing
Contributions are welcome! If you’d like to contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes:
   ```bash
   git commit -m "Description of changes"
   ```
4. Push to your branch:
   ```bash
   git push origin feature-name
   ```
5. Open a pull request.

## License
This project is licensed under MIT. See the `LICENSE` file for details.
