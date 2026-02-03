# Secure LAN Chat (E2EE)

This project is a **secure peer-to-peer chat application for local networks (LAN)**.  
It allows two users to exchange **encrypted text messages and files** without any central server.

The application is designed to work **offline**, only using a local network connection.

---

## Features

- End-to-End Encrypted (E2EE) communication  
- Secure key exchange using **RSA-2048**
- Message and file encryption using **AES-256-GCM**
- Peer-to-peer connection (no server required)
- Secure file transfer over a separate channel
- Text and visual security fingerprints for verification
- Local message history stored with SQLite
- Desktop GUI built with **PyQt6**
- Works completely offline on a local network (LAN)

---

## How It Works (Simple Explanation)

1. Each peer generates an RSA key pair.
2. Public keys are exchanged during the handshake.
3. A secure session key is generated and encrypted using RSA.
4. All messages and files are encrypted using AES-GCM.
5. Communication happens directly between peers over TCP sockets.

---

## Technologies Used

- Python
- PyQt6
- cryptography (RSA, AES-GCM)
- TCP sockets
- SQLite

---

## AI Assistance

This project was developed **with the help of Artificial Intelligence**  
(AI was used for design assistance, code review, and problem-solving support).

---

## Context

This project was written during **internet shutdowns in Iran in 2026**,  
with the goal of enabling **secure local communication when global internet access is unavailable**.

---

## Disclaimer

This project is for **educational and experimental purposes**.  
It is not intended to replace professional-grade secure messaging systems.
