# Writeup: Intro to Web 2 – Manipulating HTTP Requests

## Overview
This challenge builds on the fundamentals introduced in “Intro to Web 1” by exploring more advanced HTTP request manipulation techniques. The objective is to retrieve all four parts of a flag by interacting with a web server that enforces various client-side checks and file access restrictions.

The key lessons include:
1. Modifying **HTTP headers** (e.g., User-Agent) to bypass OS checks.
2. Changing **POST** request parameters to retrieve sensitive files.
3. Using **GET** request parameters to achieve the same result without a request body.
4. Tweaking **query parameters** (e.g., `authorized`) to gain final access.

---

## Step 1: Bypassing the Windows 95 OS Check
1. **Initial Roadblock**  
   The first page complained that the operating system was “insecure” and required upgrading to Windows 95. This restriction was implemented by checking the `User-Agent` header of incoming requests.

2. **Solution**  
   - I intercepted the request using **Burp Suite**.
   - I changed the `User-Agent` to:  
     ```
     Mozilla/4.0 (compatible; MSIE 5.0; Windows 95)
     ```
   - Upon resending the modified request, the server accepted it, granting access to the first part of the flag.

**Security Implication**: Relying on client-supplied headers like `User-Agent` for security is unsafe. Attackers can easily spoof these headers, as demonstrated here.

---

## Step 2: Using POST to Retrieve the Flag
1. **Form Functionality**  
   The website contained a form allowing the user to select which file to view (e.g., temperature or humidity logs). This form used the **POST** method, sending a parameter named `filename` in the request body (e.g., `filename=temperature-log.csv`).

2. **Manipulating the Request**  
   - I captured the POST request in my proxy.
   - Instead of sending `filename=temperature-log.csv`, I modified the parameter to:  
     ```
     filename=flag.txt
     ```
   - Resending this request caused the server to respond with the second part of the flag.

**Security Implication**: The server accepted arbitrary filenames without validating user input. Proper checks or server-side controls could prevent unauthorized file access.

---

## Step 3: Switching to GET for the Same Attack
1. **GET Parameters**  
   The challenge also showed that it’s possible to transmit parameters using **GET** by appending them to the URL (e.g., `?filename=temperature-log.csv`).

2. **Exploitation**  
   - By modifying the URL parameter directly (or via a proxy), I changed `filename` to `flag.txt`.
   - Navigating to this crafted URL returned the third part of the flag.

**Security Implication**: Both GET and POST can be manipulated. Sensitive endpoints or files should be secured server-side, rather than trusting that users will only request legitimate resources.

---

## Step 4: Final Part – “authorized” Parameter
1. **The Hidden Gate**  
   The final link redirected to `enter-security-gate.php`, which in turn led to `burn-after-reading.php`. The key parameter here was `authorized`, which the server set to `false` by default.

2. **Manipulating Authorization**  
   - If the request was sent with `authorized=false`, the file would be “burned” (deleted or made inaccessible).
   - By changing `authorized=false` to `authorized=true` before the request was sent, I gained access to the final part of the flag.

**Security Implication**: Critical authorization logic should never be controlled solely by client-side parameters. This is another example of insufficient server-side validation, allowing trivial bypass by toggling a single parameter.

---

## Conclusion and Mitigations
Through these four steps, I retrieved all parts of the flag by exploiting common weaknesses in client-side checks and server-side validation. Key takeaways and mitigation strategies include:

1. **Do Not Trust Client Headers**: User-Agent and other headers can be easily spoofed. Implement server-side checks or use tokens/certificates for genuine OS detection if truly needed.
2. **Validate Input Server-Side**: Whether using GET or POST, file parameters should be sanitized and restricted to safe paths to avoid unauthorized file disclosure.
3. **Avoid Sensitive Logic in Query Parameters**: Parameters like `authorized` can be trivially changed by attackers. Critical security decisions must happen on the server.
4. **Use Proper Authentication & Access Control**: Ensure that only authenticated and authorized users can access restricted files or pages, preventing unauthorized manipulations.

By understanding how HTTP requests can be intercepted and modified, defenders can implement stricter server-side policies and developers can avoid placing trust in easily forged client-side data.
