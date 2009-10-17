An Auth extension for the basic user model included with Sprig ORM for KO3.

Implemented as a separate module to avoid bloating or polluting Sprig core.

Adds random salt to password hash to protect against rainbow table attacks.

Uses kohana session to store authentication status.
