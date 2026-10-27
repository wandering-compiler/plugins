### An organization's members a page at a time; the new slug in OrganizationUpdated

- **Changed: `ListOrgMembers` (`GET /auth/orgs/{org}/members`) answers one page**, ordered by address: 100 members unless `page_size` asks otherwise, at most 500. `next_page_token` is set while members remain; pass it back as `page_token`. A client that read the whole list in one call reads only its first page for an organization of more than 100 members — walk the tokens.
- **`OrganizationUpdated` carries `slug`, `name` and `kind`** as they are after the change. The slug is the organization's selector (`W17-Org`, `/orgs/{org}/`); a subscriber that keys anything on it learns the new one from the event instead of reading the organization back.
