# Writeup: Bypassing the Multi-Part Web Challenge

## Overview
In this challenge, the flag was segmented into three distinct parts, each obtained through a different technique. The challenge was designed to test fundamental web security skills by combining:

1. **Part 1:** Extraction from the HTML source.
2. **Part 2:** Bypassing a JavaScript-based countdown timer.
3. **Part 3:** Intercepting an HTTP response header using a proxy tool (e.g., Burp Suite).

This writeup details my approach, the vulnerabilities identified, the exploitation steps taken, and recommendations for mitigation.

## Part 1: Extracting the Flag from the HTML Source
The first segment of the flag was directly embedded within the HTML of the challenge webpage. By viewing the page source (using the browser’s “View Page Source” function), I was able to locate the flag fragment. This method underlines the risk of exposing sensitive data directly within client-side HTML.

### Analysis & Mitigation
- **Technique:** Right-click on the webpage and select “View Page Source” to inspect the underlying HTML.
- **Finding:** A portion of the flag was directly included in the source.
- **Mitigation:** Sensitive information should never be embedded in the HTML document. Instead, such data should be generated and transmitted only after proper authentication and authorization on the server side.

## Part 2: Bypassing the JavaScript Countdown Timer
The second part of the flag was protected by a JavaScript-based countdown timer. The timer was controlled by a global variable `countDownTime`, initially set to `10000`. The `countDown()` function decrements this variable until it reaches zero, at which point it enables a button that calls the `showFlag()` function to reveal the flag.

### Code Analysis
```js
// This variable right here keeps track of how long you have to wait.
countDownTime = 10000;

function countDown() {
    countDownTime--;
    if (countDownTime > 0) {
        document.getElementById("flag-timer").innerHTML = countDownTime;
    } else {
        clearInterval(countDownIntervalId);
        document.getElementById("flag-button").innerHTML = ""+
            '<a href="." onClick="showFlag();return false;">Show flag!</a>';
    }
}

function showFlag() {
    // You don't need to understand how this part of the flag is generated.
    // All you need to know is the result of what happens here.
    const randomGenerator = mulberry32(0x5eed);
    const flag = Math.floor(randomGenerator() * 10000000000).toString(16);

    alert(`Here's the second part of your flag: ${flag}`);
}
```

### Exploitation
To bypass the enforced wait period, I manipulated the JavaScript timer using the browser's console:
```js
countDownTime = 0;
countDown();
```
By setting `countDownTime` to zero and invoking `countDown()`, the script immediately executed the branch that clears the timer and updates the UI to display the flag reveal button. This client-side vulnerability demonstrates how critical control logic should never rely solely on JavaScript.

### Mitigation
- **Server-Side Validation:** Ensure that access control mechanisms are enforced on the server side.
- **Variable Encapsulation:** Avoid exposing sensitive control variables in the global scope.
- **Additional Safeguards:** Consider using code obfuscation and integrity checks to discourage tampering, though these measures should not replace proper server-side controls.

## Part 3: Intercepting the Flag via HTTP Response Header
The third part of the flag was not visible within the HTML or JavaScript but was instead transmitted in an HTTP response header. Using Burp Suite, I intercepted the HTTP traffic between my browser and the server. In the intercepted response, I found a header containing the final fragment of the flag.

### Steps to Exploit
1. **Proxy Configuration:** I configured Burp Suite to act as an HTTP proxy and set my browser to route all traffic through it.
2. **Traffic Interception:** I refreshed the challenge webpage, allowing Burp Suite to capture the HTTP request and response.
3. **Response Analysis:** In the captured response, I inspected the HTTP headers and identified a header that contained the flag fragment.
4. **Extraction:** I then extracted the third part of the flag from the response header.

### Mitigation
- **Header Sanitization:** Avoid including sensitive data in HTTP headers. Critical information should be transmitted only within the body of secured responses and over authenticated channels.
- **Use of HTTPS:** Ensuring that communications occur over HTTPS can prevent interception by unauthorized parties.
- **Server-Side Controls:** Server logic should ensure that no sensitive information is sent unless the proper conditions are met.

## Conclusion
The multi-part flag challenge required a combination of web inspection, client-side manipulation, and network traffic interception. Each part exposed a different common security oversight:
- **HTML Exposure:** Sensitive data in the page source.
- **Client-Side Logic:** Manipulable JavaScript variables for access control.
- **Insecure Headers:** Transmitting sensitive information via HTTP response headers.

This exercise highlights the necessity for comprehensive security measures that include secure coding practices, robust server-side validations, and vigilant handling of sensitive data in all aspects of web development. Implementing these mitigations can help protect against similar vulnerabilities in production environments.
