# Cloudcreds

Secure access to your organization's AWS accounts for both programmatic and console use-case via federated identity

- ✅ Credentials are short-lived (Min: 1h, Max: 12h)
- ✅ Fine-grained RBAC (via [Google Admin CustomSchemas](https://developers.google.com/admin-sdk/directory/v1/guides/manage-schemas))
- ✅ Easy deployment (via docker, kustomize and executables)

Demo 👇

[![Demo](https://img.youtube.com/vi/onBf6JFj-IU/0.jpg)](https://www.youtube.com/watch?v=onBf6JFj-IU)

## Config Reference

*All values are default*

Can either be stored in `~/.cloudcreds.yaml` or set using env vars `CLOUDCREDS_PATH_TO=value`

```yaml
# debug flag
debug: false
client:
  # Local URL to host and open the temporary client-server to initiate auth with cloudcreds server
  url: "http://127.0.0.1:1338"
  # cloudcreds server URL
  server_url: "http://127.0.0.1:1337"
server:
  # oauth credentials
  # this is needed to allow a google federated user to assume as AWS IAM role
  # you can follow along this tutorial to generate them:
  # https://support.google.com/cloud/answer/6158849
  client_credentials: |
    {...client-credentials.json}
  # service account credentials 
  # this is needed to fetch to permitted role for a user to assumed
  # you can follow along this tutorial to generate them:
  # https://developers.google.com/admin-sdk/directory/v1/guides/delegation
  service_account_key: |
    {...service-account-key.json}
  # public URL of the server
  url: "https://cloudcreds.internal.acme.com"
  # hostname to be bind
  hostname: "127.0.0.1"
  # port to be bind
  port: 1337
  # key used to encrypt cookie session
  session_key: please-set-this-to-a-high-entropy-string
  hosted_domain: "acme.com"
```

## Getting Started

### Create an OAuth Client

Create a Google Oauth Client by following this guide: https://support.google.com/cloud/answer/6158849?hl=en

- Make sure it's an internal app usable only by your hosted domain, i.e: Emails with domain pointing to "acme.com".
- Whitelist this url pattern: `https://$CLOUDCREDS_SERVER_URL/callback`
- Generate a client credential and download the json file

### Create a Service Account

Create a Google Service account to be able to get user's assigned role in gsuite by following this guide: https://developers.google.com/admin-sdk/directory/v1/guides/delegation

- Make sure you've attached the `https://www.googleapis.com/auth/admin.directory.user.readonly` scope to the service account in gsuite settings
- Download the service account key json file

### Create an IAM Role for Web Identity

Create an IAM role on AWS with any permissions you'd like to grant this role. Next, attach a trust policy between this role and your OAuth Client to allow it to be assumed with a Web Identity.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "accounts.google.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:aud": "<google-oauth-client-id>"
        }
      }
    },
  ]
}
```

### Attach IAM Roles to GSuite Users

Follow this tutorial to create a custom attribute for your users: https://support.google.com/a/answer/6208725?hl=en

Category has to be named as `Amazon Web Service`

![aws](./docs/images/aws-custom-attributes.png)

Once that's done, attach any IAM role that has the correct trust policy attached to it:

![adding-attribs](./docs/images/adding-custom-attributes.png)

### Setup Server

If you're using docker or any container based platform you may do so like this:

```bash
docker run \
  -e CLOUDCREDS_SERVER_CLIENT_CREDENTIALS=<client-credentials-json> \
  -e CLOUDCREDS_SERVER_SERVICE_ACCOUNT_KEY=<service-account-key.json> \
  -e CLOUDCREDS_SERVER_HOSTED_DOMAIN=acme.com \
  imranismail/cloudcreds:v0 serve
```

If you want to test this out locally. Create a file in `~/.cloudcreds.yaml` with the following content

```yaml
server:
  client_credentials: |
    {...client-credentials.json}
  service_account_key: |
    {...service-account-key.json}
  hosted_domain: "acme.com"
```

Run `cloudcreds serve` to fire up a local server

### Setup Client

Create a file in `~/.cloudcreds.yaml` with the following content:

```yaml
client:
  url: "http://127.0.0.1:1338"
  server_url: "http://127.0.0.1:1337"
```

### Assuming Role

Then you can use one of the following commands to access AWS

`cloudcreds login`

or

`cloudcreds console`

Do the whole OAuth dance and once that's done you will be shown a page to select a role:

![assume-role](./docs/images/assume-role.png)

Assuming a role will either output the credentials to your CLI or redirect you to AWS Console