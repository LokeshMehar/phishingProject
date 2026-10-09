# ShieldGuard | Cyber Security Dashboard

ShieldGuard is a frontend demonstration of a highly focused cybersecurity dashboard designed to simulate strict phishing detection. It provides a clean, modern user interface specifically tailored to evaluate text, SMS messages, and URLs against strict security rules.

## Features

- **Security Overview Dashboard:** Displays high-level stats like scans today, threats blocked, and system status.
- **Fake SMS, URL & Gmail Scanner:** Simulates detection of phishing attempts using strict rules:
  - **Strict Gmail Detection:** Any email domain entered that isn't exactly `@gmail.com` is instantly flagged as fake.
  - **Fake SMS Keywords:** Detects common scam phrases used in SMS (e.g., "KYC suspended", "bank account blocked", "electricity bill").
  - **Custom URL Flagging:** Immediately flags any custom URLs (http, https, domains) found within text or SMS as dangerous.
- **Deep Sea Color Palette:** A carefully curated aesthetic using only Deep Navy Blue, Deep Ocean Blue, Steel Blue, Muted Teal, Sky Blue, and Ice Blue to create a professional and immersive security environment.

## Project Structure

This project consists of three main components:

- `index.html`: The core HTML structure for the dashboard layout, sidebar, main content, and alert modals.
- `style.css`: The stylesheet providing the deep sea color palette, responsive design, and animations.
- `script.js`: The strict JavaScript logic that powers the phishing text analysis and UI interactions.

## Getting Started

1. Clone or download the repository.
2. Open `index.html` in your preferred web browser. No local server or build tools are required as this is a vanilla static web application.

## How to use

- **Testing the Scanner:** In the "Fake SMS, URL & Gmail Scanner" section, paste a link, email snippet, or SMS.
- You can test the strict rules by typing a fake email (like `user@gmall.com`), a custom link (`http://bit.ly/scam`), or an SMS phrase (`urgent verify`). 
- Click "Run Analysis" to see the detection result in a modal alert.

## Disclaimer

This is a **demonstration dashboard**. The detection logic uses strict predefined keyword and pattern matching. It does not employ a live machine learning engine or backend server.
