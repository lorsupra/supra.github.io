# Writeup: Analysis and Exploitation of the Token-Based Login Service

## Overview
This challenge required obtaining a valid token from a network capture and then using it to authenticate against a web service. The flag was segmented into multiple parts, with this challenge focusing on retrieving a token from an HTTP response and subsequently using it to log in. The process involved three main steps:
1. Analyzing a provided packet capture (pcapng) file.
2. Extracting a token from an HTTP response header.
3. Using the token to authenticate on a web page and ultimately retrieve the flag.

## Challenge Breakdown
- **Download:** A ZIP archive containing a pcapng file for analysis in Wireshark.
- **Web Component:** The challenge website displays a login prompt ("Please login to our service") where the login text is a hyperlink.
- **Login Process:** Clicking the hyperlink takes the user to a login page with a text box and a submit button labeled "Please provide a valid token:".
- **Token Source:** The token is not directly visible on the website but is transmitted in an HTTP response header, captured in the provided pcapng file.

## Step-by-Step Exploitation Process

### 1. Packet Capture Analysis
- **Opening the Capture:** I loaded the provided pcapng file into Wireshark.
- **Locating the HTTP Traffic:** I filtered the traffic to focus on HTTP responses. One key packet caught my attention:
  
  ```
  17    11.050862377    127.0.0.1   127.0.0.1   TCP 396 1024 → 57370 [PSH, ACK] Seq=1 Ack=997 Win=512 Len=330 TSval=1006960288 TSecr=1006960287 [TCP PDU reassembled in 18]
  ```
- **Extracting the HTTP Response:**  
  I inspected this packet and copied the payload as ASCII. The HTTP response included the following header information:

  ```
  HTTP/1.1 200 OK
  Server: Werkzeug/2.2.3 Python/3.10.12
  Date: Mon, 18 Mar 2024 10:54:48 GMT
  Content-Type: text/html; charset=utf-8
  Content-Length: 57
  Set-Cookie: token=0bf77fce4af7f09d7937b59b5dfe8ce4c018ea14cd3b363d12ddc7c670ca045313aa6156b40273390e43e6128d32b993742f09d1cea1db3e3837f6082d3e6932; Path=/
  Connection: close
  ```

- **Token Extraction:**  
  The `Set-Cookie` header contains the token. I extracted the token value:
  
  ```
  0bf77fce4af7f09d7937b59b5dfe8ce4c018ea14cd3b363d12ddc7c670ca045313aa6156b40273390e43e6128d32b993742f09d1cea1db3e3837f6082d3e6932
  ```

### 2. Token Submission
- **Navigating to the Login Page:**  
  The website’s homepage displayed a hyperlink with the text "Please login to our service." I clicked this link, which directed me to a login page containing a text box and a submit button prompting, "Please provide a valid token:".
- **Submitting the Token:**  
  I entered the extracted token into the text box and clicked the submit button. The server accepted the token and responded with a confirmation page stating:
  
  ```
  Thx for your request! Please go home now!
  ```

### 3. Retrieving the Flag
- **Following the Hyperlink:**  
  The confirmation page included a hyperlink labeled "home." Upon clicking this link, I was redirected to a final page that displayed the complete flag message:
  
  ```
  Welcome to the CSCG Flag Service serving some flags: CSCG{sn00py_sn00p_w1th_w1resh4rk!}
  ```

## Vulnerability Analysis and Mitigation
- **Token Exposure in Cleartext:**  
  The token was transmitted in an HTTP response header, making it susceptible to interception by anyone with access to the network capture. This issue could be mitigated by:
  - Using secure HTTPS communications to encrypt the entire HTTP exchange.
  - Avoiding the inclusion of sensitive tokens in easily accessible HTTP headers.

- **Client-Side Trust:**  
  The service trusted the token extracted from the network capture without additional server-side verification. Strengthening authentication mechanisms by incorporating server-side checks and session management could reduce the risk of token hijacking.

- **Forensic Analysis Importance:**  
  This challenge underscores the need for thorough network monitoring and analysis in both offensive and defensive cybersecurity contexts. Tools like Wireshark and Burp Suite can be invaluable in identifying and mitigating potential vulnerabilities.

## Conclusion
The challenge combined elements of network forensics and web security, requiring a multifaceted approach:
- I analyzed the pcapng file in Wireshark to locate a critical HTTP response.
- I extracted a valid token from the `Set-Cookie` header in the HTTP response.
- I used this token to authenticate on the web service, ultimately retrieving the flag:  
  `CSCG{***********REDACTED********}`

This exercise highlights the importance of securing token transmission and enforcing robust server-side authentication mechanisms. It also demonstrates how network forensics can reveal sensitive information when proper security measures are not in place.
