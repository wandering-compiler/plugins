### An API token names the products' roles it may use (`product_roles` with `api_token`)

- `CreateApiTokenReq.product_roles` and `IssueBotTokenReq.product_roles` name the products' roles a token may use, each one of the catalogue (`PRODUCT_UNKNOWN`, `PRODUCT_ROLE_UNKNOWN` otherwise). A product is answered the roles the token names that a role its holder holds there covers (a holder of alpha's editor may mint a token for alpha's viewer).
- **A token minted narrow stays narrow toward the products.** One with a `permission_subset` and no product role now reaches the products with **no** role; until now it carried every product role of its holder. A token narrowed on neither axis carries them all, as before, and so does a session.
- A migration adds the table `TokenProductRole` (with `product_roles`).

### A backoffice method held realm-wide acts realm-wide from inside an organization

- The backoffice's methods that refuse inside an organization — packages, hosts, sign-up policies, the products' roles and plans — now act realm-wide for a caller who holds them through a realm-wide role, whatever organization the request acts in (named, or the caller's only one inferred). Until now they refused (`PACKAGES_REALM_ONLY`, `HOSTS_REALM_ONLY`, …) and an operator who was also a member of one organization needed a second account or `org_from_sole_membership: false`.
- A member who holds such a method only inside an organization is refused as before. The grant plugin's envelope decisions still need a request acting in no organization.
