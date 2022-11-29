# Traefik Plugin For Rate Limiting Incoming Telegram Messages

![Github Actions](https://img.shields.io/github/workflow/status/bitzlato/traefik-telegram-ratelimiter/Audit?style=flat-square) ![Go Report](https://goreportcard.com/badge/github.com/bitzlato/traefik-telegram-ratelimiter?style=flat-square) ![Go Version](https://img.shields.io/github/go-mod/go-version/bitzlato/traefik-telegram-ratelimiter?style=flat-square) ![Latest Release](https://img.shields.io/github/release/bitzlato/traefik-telegram-ratelimiter/all.svg?style=flat-square) 

This traefik plugin allows you to define limits for incoming telegram messages based on the messages' IDs. Define exceptions for certain IDs with higher limits and to block certain IDs at all.

## Sample configuration

The following code snippet is a sample configuration for the dynamic file based provider, but this plugin works with all other configuration providers as well.

```yaml
# config.yml
api:
  dashboard: true
  insecure: true # do not use `insecure: true` in production

experimental:
  plugins:
    traefik-telegram-ratelimiter:
      moduleName: github.com/bitzlato/traefik-telegram-ratelimiter
      version: "v0.0.5"

entryPoints:
  https:
    address: ":443"
    forwardedHeaders:
      insecure: true

providers:
  file:
    filename: rules.yml

# rules.yml
http:
  routers:
    my-router:
      entryPoints:
        - https
      middlewares:
        - tg-ratelimit
        - strip-webhook
      service: tg-bot
      rule: Path(`/webhook/tg-bot`)

  services:
    tg-bot:
      loadBalancer:
        servers:
          - url: http://tg-bot:8000

  middlewares:
    tg-ratelimit:
      plugin:
        traefik-telegram-ratelimiter:
          hitTableSize: 50000
          limit: 6000
          whitelistLimit: -1
          expire: 86400 # 24 hours
          whitelist: "/srv/config/tg-bot/whitelist.ids"
          blacklist: "/srv/config/tg-bot/blacklist.ids"
    strip-webhook:
      stipPrefix:
        prefixes:
          - "/webhook/tg-bot"
```

## Configuration

This plugin supports the following configuration parameters:

- **hitTableSize** -- maximum size of the table to keep hit records. On overflow the oldest records will be overwritten with the new ones. Default value: `50000`
- **expire** -- the duration in seconds to keep the ID record since the first occurence of the ID in the incoming telegram message. After that time the hits with the same ID will start to count since 0 again. Default value: `86400` (24 hours)
- **limit** -- maximum number of hits (messages) to allow during the `expire` period. `-1` means the limit is not applied. `0` -- no hits allowed at all. Default value: `-1` (do not apply hit limit)
- **whitelistLimit** -- maximum number of hits to allow for IDs found in the `whitelist` file. Has the same special cases as for the `limit` parameter. Default value: `-1` (do not apply hit limit)
- **whitelist** -- path to the file containing telegram IDs to apply `whitelistLimit` to. The file should contain each numeric ID on a separate line. Default value: `nil`
- **blacklist** -- path to the file containing telegram IDs to block right away. Hits counting is not applied to the blacklisted IDs. Default value: `nil`
