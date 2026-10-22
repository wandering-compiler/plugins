### Personal API tokens in an organization (read first)

- A person in an organization no longer holds an API-realm role (see `ROLE_IS_FOR_BOTS` under Fixed), so a personal API token (`CreateApiToken`) used in an organization authenticates and is granted nothing. Before upgrading, move every script, CI job and integration that calls with a person's API token to a machine account: `CreateBot`, give it its roles (`SetBotRoles` with `bot_roles`), and mint its token with `IssueBotToken` (`service_account`). A project that issues no personal API tokens has nothing to do.
