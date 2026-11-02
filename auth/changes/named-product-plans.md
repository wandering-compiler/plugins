### Named product plans (named_product_plans, off by default)

A plan across your products can now be defined once in the backoffice and
given to organizations: a tariff such as "basic" or "pro". Its lines are a
product's role or a whole product, the same as an organization's own plan
lines. An organization on a plan holds its plan's lines and its own lines
together: its own add to the plan and are never replaced by it. Editing a
plan changes every organization on it on its next request.

- `GET` / `POST /auth/admin/product-plans`, `DELETE /auth/admin/product-plans/{plan_id}`,
  `PUT /auth/admin/product-plans/{plan_id}/lines`, `POST …/lines/remove`
- `PUT /auth/admin/orgs/{org_id}/product-plan-assignment` with `{"plan_id": "…"}`
  (an empty `plan_id` takes the organization off its plan)
- `GET /auth/admin/orgs/{org_id}/product-plan` and `GET /auth/orgs/{org}/product-plan`
  now also return `plan_id`, `plan_name` and `plan_lines`.

Enable `named_product_plans` (it requires `product_plans`) and regenerate. The
three new tables need a migration. A plan that organizations are on cannot be
deleted (`PRODUCT_PLAN_IN_USE`); move the organizations to another plan first.
