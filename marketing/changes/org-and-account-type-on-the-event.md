### The organization and the account type go on the event, not the contact

- Every event carries `w17_org_id` (the organization the request acted in) and `w17_account_type` (the caller's kind of membership there, from auth's `membership_kinds`), each only when the record has it: a project without organizations or kinds sends neither.
- The contact no longer gets `W17_ORG_ID`. A contact is the person, and a person may work in two organizations at once; the attribute held whichever organization the last recorded request named. The plugin no longer creates the attribute either. **Upgrading:** an account that has it keeps it with its last values; delete the attribute in Brevo (Contacts → Settings → Contact attributes) and segment on the events' `w17_org_id` / `w17_account_type` instead.
