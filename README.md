## Cloudcreds

Secure access to your organization's AWS accounts for both programmatic and console use-case via federated identity

- ✅ Credentials are short-lived (Min: 1h, Max: 12h)
- ✅ Fine-grained RBAC (via [Google Admin CustomSchemas](https://developers.google.com/admin-sdk/directory/v1/guides/manage-schemas))
- ✅ Easy deployment (via docker, kustomize and executables)

Demo 👇

[![Demo](https://img.youtube.com/vi/onBf6JFj-IU/0.jpg)](https://www.youtube.com/watch?v=onBf6JFj-IU)

## Default Config

```yaml
client:
  # Debug flag
  debug: true
  # Local URL to host and open the temporary client-server to initiate auth with cloudcreds server
  url: "http://127.0.0.1:1338"
  # cloudcreds server URL
  server_url: "http://127.0.0.1:1337"
server:
  # debug flag
  debug: true
  # public URL of the server
  url: "https://cloudcreds.internal.acme.com"
  # hostname to be bind
  hostname: "127.0.0.1"
  # port to be bind
  port: 1337
  # key used to encrypt cookie session
  session_key: please-set-this-to-a-high-entropy-string
  # oauth credentials
  client_id: "<google-oauth-client-id>"
  client_secret: "<google-oauth-client-secret>"
  # supports only google for now
  # future plans includes github, auth0 and other oidc adapters
  issuer_url: "https://accounts.google.com"
  # your organization hosted domain e.g: youremail@hosted_domain.com
  hosted_domain: "*"
  # these are the default scopes needed
  scopes:
  - email
  - profile
  - openid
  - https://www.googleapis.com/auth/admin.directory.user.readonly
```