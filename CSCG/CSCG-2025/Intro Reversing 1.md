# Writeup: Intro to Reversing 1 – ELF x86_64 Analysis

## Overview
In this challenge, we were provided with a 64-bit ELF executable (`rev1`) and tasked with discovering a hidden password. Once identified, this password could be used to authenticate with a remote service and reveal a corresponding flag. Below is a step-by-step breakdown of how I approached the problem, without disclosing any sensitive strings or flags.

---

## Step 1: Initial File Inspection
1. **File Command**  
   I began by running the `file` command to confirm the binary type:
   ```bash
   file rev1
   ```
   This confirmed it was a **64-bit ELF** executable for Linux.

2. **Basic Checks**  
   - **Permissions**: Verified it was executable.  
   - **Hash/Signature**: (Optional) Sometimes checking the hash can ensure file integrity.

---

## Step 2: Strings Analysis
To get a quick overview of potentially interesting text within the binary, I used the `strings` command:

```bash
strings rev1 | less
```

- **Suspicious Strings**: Among the output, I found references to standard C library functions (e.g., `strcmp`) and some debugging or build-related strings (e.g., `GCC: (Debian 8.3.0-6) 8.3.0`).
- **Potential Password**: Notably, one string stood out as a possible password. I will **redact** this sensitive string here, but it was clearly identifiable in the list of strings.

---

## Step 3: Testing the Password
1. **Remote Service Interaction**  
   The challenge provided a remote service via `ncat`. When connecting, the binary prompted for a password.
2. **Password Submission**  
   I entered the redacted password discovered in the strings output. The service accepted this password and displayed a success message indicating that the password was correct.

---

## Step 4: Observations & Additional Clues
1. **Flag Retrieval**  
   Once authenticated, the service revealed the content of the challenge flag. (All actual flag details are omitted here.)
2. **`flag.txt` Reference**  

---

## Lessons Learned & Mitigation
- **Storing Sensitive Data in Binaries**: Placing passwords in plaintext within an executable makes them easily discoverable through simple tools like `strings`. A better approach would be to store credentials securely or require runtime user input, possibly verified by a remote server.
- **Obfuscation Is Not Security**: Even minimal static analysis techniques (e.g., using `strings`) can reveal hidden text. True security relies on robust encryption and proper authentication mechanisms.
- **Static Analysis Workflow**:  
  1. **Check file type** (`file`)  
  2. **Inspect strings** (`strings`)  
  3. **Look for suspicious references** (`flag`, known library calls, potential credentials)  
  4. **Test discovered values** in the actual challenge environment  

---

## Conclusion
By performing a straightforward static analysis of the ELF binary using `strings`, I discovered a suspicious password-like string. Submitting this password to the remote service validated its correctness and granted access to the challenge’s flag. This challenge underscores the ease with which hardcoded secrets can be uncovered and emphasizes the importance of avoiding embedding sensitive data directly in compiled binaries.