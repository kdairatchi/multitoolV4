
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


~Option1~
```
PyQt5==5.15.9
requests==2.31.0
nmap-python==0.7.1
telethon==1.29.1
pywhatkit==5.4
facebook-sdk==3.1.0
openai==0.28.0
browser-cookie3==0.17.3
autopy==4.0.0
```

~Option2~
# Update package list and install system dependencies
```
sudo apt update && sudo apt install -y python3-pip python3-venv nmap
```

# Install required Python packages using pip (for system-wide installation)
```
pip3 install PyQt5==5.15.9 requests==2.31.0 nmap-python==0.7.1 telethon==1.29.1 pywhatkit==5.4 facebook-sdk==3.1.0 openai==0.28.0 browser-cookie3==0.17.3 autopy==4.0.0
```
~Option3~
# Create a virtual environment
```
python3 -m venv myenv
source myenv/bin/activate
```
# Install Python packages in the virtual environment
```
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
### v4.0 - Final Release:
Sure! Here is a comprehensive guide to set up, run, and maintain your repository step by step.

---

# 📂 v4.5 - MultiToolV4 - Full Setup and User Guide Update
---

## ⚙️ Features

- **Telegram Scraping**: Scrape and monitor Telegram groups using **Telehunting**.
- **WhatsApp Messaging**: Send instant WhatsApp messages using **pywhatkit**.
- **Network Scanning**: Scan networks for vulnerabilities using **Nmap**.
- **OpenAI-Powered Error Handling**: Use **OpenAI** to suggest fixes for errors in real-time.
- **Facebook Automation**: Post updates to your Facebook page using **Facebook Business SDK**.
- **User Interface**: Built using **PySide6** for a robust GUI.

---

## 🚀 Step-by-Step Setup Guide

### 1. **Clone the Repository**

Start by cloning the repository to your local machine:

```bash
git clone https://github.com/yourusername/multitoolv4.git
cd multitoolv4
```

### 2. **Set Up a Python Virtual Environment**

It is highly recommended to use a virtual environment to keep your dependencies isolated and prevent conflicts with other packages on your system.

#### For Linux/MacOS:

```bash
python3 -m venv multitool_env
source multitool_env/bin/activate
```

#### For Windows:

```bash
python -m venv multitool_env
multitool_env\Scripts\activate
```

### 3. **Install Python Dependencies**

Once the virtual environment is activated, install the required Python libraries. We've provided a `requirements.txt` file, so just run:

```bash
pip install -r requirements.txt
```

This will install all the necessary packages including:
- **PySide6** (GUI framework)
- **requests** (HTTP requests)
- **nmap-python** (Nmap wrapper for Python)
- **pywhatkit** (WhatsApp automation)
- **browser-cookie3** (Access browser cookies)
- **facebook-business** (Facebook API SDK)
- **openai** (OpenAI API)
- **pyautogui** (Automation)
- **telehunting** (Telegram scraping library)
- **asyncio** (Asynchronous programming)

---

## 📄 Configuration

Before running the tool, you need to set up the API credentials for the different services you're integrating with.

### 1. **API Credentials Setup**

Create a file named `api_credentials.json` in the `config/` directory with the following structure:

```json
{
  "facebook_access_token": "YOUR_FACEBOOK_ACCESS_TOKEN",
  "whatsapp_phone_number": "YOUR_WHATSAPP_PHONE_NUMBER",
  "telegram_username": "YOUR_TELEGRAM_USERNAME",
  "openai_api_key": "YOUR_OPENAI_API_KEY"
}
```

Replace the placeholders with your actual API credentials:
- **Facebook Access Token**: You can get this from the Facebook Developer portal.
- **WhatsApp Phone Number**: This is your WhatsApp number for sending messages via **pywhatkit**.
- **Telegram Username**: Required for **Telehunting** to scrape data from Telegram groups.
- **OpenAI API Key**: Get this from the **OpenAI** Developer Console.

---

## 🔧 Running the Application

Now, you're ready to run **MultiToolV4**! Simply execute the following command to launch the GUI:

```bash
python multitoolv4.py
```

This will open the PySide6-based GUI, which you can use to interact with the various features.

---

## 🧭 How to Use the Tool

Once the GUI is up and running, here's how to use each feature:

### 1. **Bot Setup**
- Navigate to the **Bot Setup** tab.
- Make sure your API credentials are correctly loaded from `config/api_credentials.json`.
- Click the **Setup Bots** button to initialize bots for Telegram, WhatsApp, and Facebook.
- You will see output in the log window confirming that the bots are set up.

### 2. **Telegram Scraping**
- You can scrape messages from a Telegram group by specifying the group's ID.
- The last 5 messages will be fetched and displayed in the GUI.

### 3. **WhatsApp Messaging**
- You can send a message to a WhatsApp number using **pywhatkit**. The message will be delivered instantly and logged in the GUI.

### 4. **Network Scanning**
- Go to the **Victim Monitor** tab, enter a target IP address, and click **Add Victim**.
- **Nmap** will scan the IP for open ports and vulnerabilities. The result will be logged in the GUI.
  
### 5. **Backdoor Setup**
- In the **Bot Setup** tab, you can start a backdoor listener on a specified IP and port.
- Once a connection is made, it will be logged, and the user will be notified via Telegram and WhatsApp.

### 6. **AI Error Handling**
- If any errors occur during execution, they will be caught and handled by the **OpenAI API**. The tool will suggest a possible fix, which is displayed in the **Error Handling** tab.

---

## 🛠️ Debugging & Troubleshooting

Here are some common issues you might encounter and how to resolve them:

### 1. **Missing API Credentials**
- If any of the API credentials are missing, you will see an error message in the GUI. Ensure your `api_credentials.json` file contains all necessary information.

### 2. **Error Handling by OpenAI**
- If the **OpenAI** API fails, check your API key and usage limits.
- Make sure you are connected to the internet for the API to function correctly.

### 3. **Facebook SDK Errors**
- Ensure that your Facebook Access Token is valid.
- Make sure the Facebook App is in **Development Mode** and has the necessary permissions for automating posts.

### 4. **Nmap Scanning Errors**
- If **Nmap** fails to scan a target, make sure that Nmap is installed on your system and that the target IP is reachable.

---

## 📋 Code Overview

### Main Features:

1. **Logging Setup**:
   - Logging is configured to write to `multi_tool.log` with rotation based on size. Logs can be found in the `logs/` folder.

2. **Bot Notifications**:
   - **WhatsApp**: Sends notifications using `pywhatkit`.
   - **Facebook**: Posts updates to your Facebook page using the **Facebook Business SDK**.

3. **Telegram Scraping**:
   - **Telehunting** scrapes the last 5 messages from a target Telegram group.

4. **Network Scanning**:
   - **Nmap** scans a target IP for vulnerabilities and sends notifications based on the results.

5. **Backdoor Setup**:
   - Sets up a backdoor listener on a specified IP and port, notifying users of connections.

6. **Error Handling**:
   - **OpenAI** is used to suggest fixes for errors in real-time.

---

## 🛠️ Code Snippets

### 1. WhatsApp Notification

```python
def whatsapp_notify(message, phone_number, output_area):
    """Send a WhatsApp message using pyWhatKit."""
    try:
        kit.sendwhatmsg_instantly(phone_number, message)
        output_area.append("WhatsApp message sent successfully.\n")
        logging.info(f"WhatsApp message sent to {phone_number}")
    except Exception as e:
        handle_exception(e, output_area)
```

### 2. Telegram Scraping with Telehunting

```python
async def telegram_hunting(output_area):
    """Use Telehunting to scrape data from Telegram chats and groups."""
    try:
        telehunting = Telehunting(username=TELEGRAM_USERNAME)
        target_group = 'target_group_id'  # Replace with your target group ID
        await telehunting.connect()

        messages = await telehunting.get_messages(target_group, limit=5)
        output_area.append(f"Monitoring Telegram Group: {target_group}\n")
        for msg in messages:
            output_area.append(f"Message: {msg.message}\n")

        await telehunting.disconnect()

    except Exception as e:
        handle_exception(e, output_area)
```

### 3. Nmap Scanning

```python
def scan_target(rhost, output_area):
    """Scan target using Nmap."""
    try:
        nm = nmap.PortScanner()
        nm.scan(rhost, arguments=NMAP_ARGS)
        result = f"Target OS: {nm[rhost]['osclass'][0]['osfamily']}\n{nm.csv()}"
        output_area.append(result)
    except Exception as e:
        handle_exception(e)
```

---



## 🛠️ Contributing

If you'd like to contribute to this project, follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Push your changes and create a pull request.

---

## 🚀 