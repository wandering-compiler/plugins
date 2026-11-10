### The sign-up date is no longer lost in the first moments of a fresh account

The consent attribute, `W17_MARKETING_CONSENT_AT` and `W17_SIGNED_UP_AT` are created before the plugin subscribes to auth's events, waiting at most 5 seconds for Brevo at boot. They used to be created in the background, and a sign-up handled before `W17_SIGNED_UP_AT` existed lost its date for good (Brevo drops an attribute the account lacks, silently). The activity attributes are still created in the background.
