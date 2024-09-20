
# 🎯 MultiToolV4 - Complete Setup and Usage Guide By Kdairatchi

Welcome to **MultiToolV4** – your all-in-one tool for network scanning, bot notifications, victim monitoring, and error handling, all powered by Python, `PyQt5` for the GUI, and asynchronous bot notifications. This guide will take you through everything you need to set up, run, and understand the tool. 😄

## 🔥 Features
- **Asynchronous Telegram Notifications** using `asyncio` and `Telethon`.
- **WhatsApp Messaging** through `pywhatkit`.
- **Real-time Vulnerability Monitoring**.
- **Error Handling and Fix Suggestions** using OpenAI.
- **Backdoor Management** with threading for non-blocking execution.
- **Cross-platform GUI** with `PyQt5`.

---

## 🛠️ Requirements and Compatibility

The tool requires the following libraries to run smoothly. All packages are verified for compatibility.

| 🛠️ **Library**      | 📌 **Version** | 📝 **Description**                              |
|---------------------|----------------|------------------------------------------------|
| **PyQt5**           | 5.15.9         | GUI framework                                  |
| **requests**        | 2.31.0         | HTTP requests library                          |
| **nmap-python**     | 0.7.1          | Python wrapper for Nmap                        |
| **telethon**        | 1.29.1         | Telegram bot integration                       |
| **pywhatkit**       | 5.4            | WhatsApp messaging integration                 |
| **facebook-sdk**    | 3.1.0          | Facebook API integration                       |
| **openai**          | 0.28.0         | OpenAI API for AI-guided error handling        |
| **browser-cookie3** | 0.17.3         | Cookie management for browsers                 |
| **autopy**          | 4.0.0          | Cross-platform GUI automation                  |
| **asyncio**         | Native to Python 3.3+ | Asynchronous I/O framework |

---

## 📋 Getting Started

### 1. 🚀 Environment Setup

To ensure compatibility, it's best to use a **virtual environment**. This isolates your dependencies and prevents conflicts with system packages.

#### For Linux/MacOS:
```bash
python3 -m venv myenv
source myenv/bin/activate
```

#### For Windows:
```bash
python -m venv myenv
myenv\Scripts\activate

git clone https://github.com/kdairatchi/multitoolV4
cd multi_toolV4
```

```
git clone https://github.com/kdairatchi/multitoolV4
cd multi_toolV4
```

### 2. 📥 Installing Dependencies

You can install all the necessary libraries by using the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

> Here's the content of the `requirements.txt` file to ensure that all dependencies are installed correctly:

```txt
~Option1~
PyQt5==5.15.9
requests==2.31.0
nmap-python==0.7.1
telethon==1.29.1
pywhatkit==5.4
facebook-sdk==3.1.0
openai==0.28.0
browser-cookie3==0.17.3
autopy==4.0.0

~Option2~
# Update package list and install system dependencies
sudo apt update && sudo apt install -y python3-pip python3-venv nmap

# Install required Python packages using pip (for system-wide installation)
pip3 install PyQt5==5.15.9 requests==2.31.0 nmap-python==0.7.1 telethon==1.29.1 pywhatkit==5.4 facebook-sdk==3.1.0 openai==0.28.0 browser-cookie3==0.17.3 autopy==4.0.0

~Option3~
# Create a virtual environment
python3 -m venv myenv
source myenv/bin/activate

# Install Python packages in the virtual environment
pip install PyQt5==5.15.9 requests==2.31.0 nmap-python==0.7.1 telethon==1.29.1 pywhatkit==5.4 facebook-sdk==3.1.0 openai==0.28.0 browser-cookie3==0.17.3 autopy==4.0.0
```

### 3. ✅ Verifying Installation

After installing the packages, you can check for any dependency issues with:

```bash
pip check
```

---

## 🧰 Configuration Setup

### 1. 🔑 API Keys

Make sure to place your API keys for Telegram, WhatsApp, Facebook, and OpenAI in a `config/api_credentials.json` file.

Here's an example `api_credentials.json` file:

```json
{
  "telegram_api_id": "YOUR_TELEGRAM_API_ID",
  "telegram_api_hash": "YOUR_TELEGRAM_API_HASH",
  "telegram_bot_token": "YOUR_TELEGRAM_BOT_TOKEN",
  "facebook_access_token": "YOUR_FACEBOOK_ACCESS_TOKEN",
  "whatsapp_phone_number": "YOUR_WHATSAPP_PHONE_NUMBER",
  "openai_api_key": "YOUR_OPENAI_API_KEY"
}
```

> **Important**: Ensure that this file is correctly formatted, and all necessary keys are provided before running the tool.

---

## 🏃 Running the Application

Now that everything is set up, you can launch the **MultiToolV4** with the following command:

```bash
python multitoolv4.py
```

This will launch the PyQt5 GUI, and from here, you can interact with the tool's features:

1. **Bot Setup**: Set up Telegram, WhatsApp, and Facebook bots.
2. **Victim Monitoring**: Monitor vulnerable devices on the network.
3. **Error Handling**: Get real-time AI-driven suggestions when errors occur.

---

## 🔍 Features Breakdown

### 1. ⚙️ Bot Setup

**Telegram**, **WhatsApp**, and **Facebook** bots are configured to send notifications when certain events (like vulnerabilities detected) occur.

- **Telegram**: Messages are sent asynchronously to avoid blocking the main event loop. Make sure your `telegram_api_id`, `telegram_api_hash`, and `telegram_bot_token` are correct.
  
  Example code for sending notifications:
  ```python
  async def telegram_bot_notify(message, output_area):
      await telegram_client.start(bot_token=BOT_TOKEN)
      await telegram_client.send_message('me', message)
      output_area.append("Telegram notification sent.\n")
  ```

- **WhatsApp**: Notifications are sent using `pywhatkit`. Make sure to enter the correct phone number in the format required.

- **Facebook**: Messages are posted using the Facebook Graph API. Make sure your access token is valid.

### 2. 🔍 Network Scanning

**Nmap** is used for scanning network devices to identify vulnerabilities and services.

- **scan_target(rhost, output_area)**: This function takes the target's IP address and returns the scanned results.

Example usage:
```python
nm = nmap.PortScanner()
nm.scan(rhost, arguments=NMAP_ARGS)
output_area.append(f"Target OS: {nm[rhost]['osclass'][0]['osfamily']}\n{nm.csv()}")
```

### 3. 🔑 Backdoor Setup

You can use the **create_backdoor** function to open a backdoor on the target machine. This process runs in the background on a separate thread to ensure the GUI remains responsive.

Example usage:
```python
threading.Thread(target=create_backdoor, args=(LHOST, 8080, self.bot_output, self.stop_event), daemon=True).start()
```

### 4. 💡 AI Error Handling

Whenever an error occurs, **OpenAI** is used to suggest fixes in real time. This feature leverages the OpenAI API to analyze the error and provide possible solutions.

Example code:
```python
def detect_and_fix_errors(error_message, output_area):
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt=f"Error detected: {error_message}. Suggest a fix.",
        max_tokens=150
    )
    suggestion = response.choices[0].text.strip()
    output_area.append(f"AI Suggestion: {suggestion}")
```

---

## 🛑 Troubleshooting and Known Issues

### 1. **Telegram Compatibility** ⚡
When using `telethon` with `asyncio` in a PyQt5 application, avoid using `asyncio.run()`. Use `asyncio.create_task()` to manage asynchronous calls properly.

### 2. **PyQt5 Event Loops** 🖼️
Ensure that the main PyQt5 event loop remains unblocked by properly managing threading for long-running operations like backdoor setup and scanning.

### 3. **Nmap Dependency** 🔍
Ensure that **nmap** is installed on your system. You can install it as follows:

#### For Linux:
```bash
sudo apt install nmap
```

#### For MacOS:
```bash
brew install nmap
```

---

## 👨‍💻 Contributing

Contributions are welcome! If you encounter bugs, have feature requests, or want to contribute, feel free to open an issue or submit a pull request. Let's make **MultiToolV4** even better together! 🤝

---

## 📃 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

Thanks to all the contributors and the developers of these amazing libraries! Special thanks to **OpenAI**, **Telethon**, **PyQt5**, and others for their valuable tools that power this project! 🙌

---

## 🎨 Screenshots

![MultiToolV4 Screenshot](https://example.com/screenshot1.png)
_Showing the GUI in action._

---

## 📝 Changelog

### v4.0 - Final Release:
- Added **asynchronous notifications** using `asyncio`.
- Improved **error handling** with real-time suggestions using **OpenAI**.
- Enhanced **victim monitoring** and **backdoor setup**.
- Fixed compatibility issues with **PyQt5** and other libraries.

---

This README should now cover every aspect of your repository in an engaging and clear manner. Let me know if you need further customization or improvements! 😊
--
