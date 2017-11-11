# NSocker the namespaced socket server

Did you ever feel like running a part of your app with different networking
settings? Under VPN, different routes or kernel settings? Not feeling like
abusing a SOCKS proxy for that? Well, [Linux network
namespaces](http://man7.org/linux/man-pages/man8/ip-netns.8.html) are meant just
for that, but have some limitations. NSocker is here to help.

The idea is simple - nsocker is a daemon you run in a network namespace you
create. It listens on a Unix socket and creates sockets for anyone who asks. The
important bit is sockets remember their namespace, so your program (the nsocker
client) gets a socket that obeys the rules of the other network namespace.

## Example

Let's say you have a simple Python application where you need to access a
web-page from a different network namespace:
```
import urllib.request
import nsocker

nsocker.push('/run/nsocker/vpn')
urllib.request.urlopen('http://example.com')
nsocker.pop()
```

Create your network namespace, let's name it 'vpn' and [run OpenVPN in the
namespace](http://www.naju.se/articles/openvpn-netns.html). Then, run the
nsocker daemon in the namespace using `ip netns exec vpn nsocker
/run/nsocker/vpn` (make sure `/run/nsocker directory` exists). 

Now you can run your app (`app.py`):
```
LD_PRELOAD=/usr/local/lib/libnsocker-preload.so python app.py
```
Congrats, the `http://example.com` fetch was executed over OpenVPN.

Alternatively, if you don't need to control the NSocker context from within your
app, just run:

```
LD_PRELOAD=/usr/local/lib/libnsocker-preload.so NSOCKER_SERVER=/run/nsocker/vpn python app.py
```

## Usecases

Theoretically, you can accomplish everything written above with a pair of
`setns` calls (pop in a namespace, grab a socket, leave the namespace). So why
NSocker?

You don't need CAP_SYS_ADMIN, the access to NSocker is a Unix socket protected
by classic Unix permissions. You can sort-of work-around the above using user
namespaces. But some distributions do not enable them because of security
concerns (ArchLinux as of late 2017), and you will not be able to get back to
the original namespace, so you have to fork. Also you can not bind-mount them as
an ordinary user, so you will need a running process (so why not NSocker?).

So the typical use case for NSocker is building a web scraper. You want it to
have a control interface, but access the web pages using a VPN.

If you have control over yor application, you can use the NSocker C client API
explicitely and not redirect all `socket` calls.

Finally, you don't have to use it with network namespaces, but I am not sure
why to do that... But maybe there is a good reason? Impersonating other user?

Or you could extend NSocker to grab you other interesting things? (root
directory handle out of mount namespace maybe?)

## Installing

```
mkdir build
cd build
cmake ..
make
sudo make install
echo 'PROFIT'
```

## Package contents

- NSocker daemon
- C client API
- Python client API (extension)
- `socket` call redirector (using `LD_PRELOAD`)

## Limitations
 - The `LD_PRELOAD` component does not affect code inside LibC, so for example DNS
   (gethostbyname) can not be redirected.
 - The NSocker client API is rather simple and single-threaded. The `LD_PRELOAD`
   library creates a single client per thread.
