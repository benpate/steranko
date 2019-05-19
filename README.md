# Steranko 🔐

## Security and Identity Management for Go

## This project is a work-in-progress, and should NOT be used by ANYONE, for ANY PURPOSE, under ANY CIRCUMSTANCES.  It is NOT READY FOR PRIME TIME, and is essentially GUARANTEED to blow up your computer, send your cat into an infinite loop, and combine your hot and cold laundry into a single cycle.

Steranko is a micro-service for user authentication, authorization, and identity management.


## Project Goals

* Create a first class, open source user management system in Go.
* Hashed passwords using bcrypt
* Lock out user accounts after N failed attempts.

* Support user account creation
* Password strength checking
* Password vulnerability via HaveIBeenPwned API.
* Identify malicious users with a (relatively) invisible CAPTCHA system
	* Track javascript events during signup (keyup, keydown, mousemove, click)
	* Track timing of events.  They must not be too fast, or too consistent.
	* Something to prevent requests from being forwarded to an actual human.
	* Math problems?
	* Geolocation.
