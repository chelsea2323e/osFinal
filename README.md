# Classroom Access System

    npm install
    cp .env.example .env     # then set JWT_SECRET
    npm start                # http://localhost:3000

## Built-in guard account
Created automatically on first start (when no guard exists yet):

- Role: Guard
- Email: guard@cvsu.edu.ph  (change with GUARD_EMAIL in .env)
- Password: Guard@12345  (or GUARD_PASSWORD in .env). The default must be changed at first sign-in.

There is no administrator role. Guards are the only users who can create, reset and delete accounts
(Student, Professor and Guard) from the Accounts tab. The last remaining guard account cannot be deleted.

## Keeping data between restarts
Accounts, passwords, requests and proof photos are stored in `data.json` and `uploads/`.
Many hosts (Render, Railway, Heroku, Replit, free tiers) erase the app folder on every restart or
redeploy. When that happens the built-in guard is re-created with the default password.
Mount a persistent disk/volume and set `DATA_DIR` to its path (for example `DATA_DIR=/var/data`)
so both are kept there.
