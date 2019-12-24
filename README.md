## Blacklisting and tokenrevoking

Maybe a simple redis database that stores the black list which consists of:

- still valid access tokens
- still valid refresh tokens

Whenever a user uses a blacklisted token we send response as if he has an expired token.

When tokens in the database expire we remove them (to save space, possible using a job that checks for expired tokens)
