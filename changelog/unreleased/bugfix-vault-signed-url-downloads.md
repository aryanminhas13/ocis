Bugfix: Fix file and folder downloads in vault mode

Downloading a file in the vault failed with a 403 error. Downloads use a signed
link that carries no login token, so the proxy relies on a remembered MFA
status of the user. That status was never saved, because the proxy tried to
store it before it knew which user sent the request. It is now saved once the
user is known, and a download is accepted as long as the user had a request with
MFA within the configured MFA session duration.

Downloading a folder or several files in the vault failed with a 404 error,
because the web UI requested the signing key from a wrong address while in vault
mode. The request now goes to the correct address.

https://github.com/owncloud/ocis/pull/13097
