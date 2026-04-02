<a id="top"></a>

# Table of Contents
- [Description](#description)
- [Main Features](#main-features)
- [Tech Stack](#tech-stack)
- [Data Model](#data-model)
- [Architecture Diagram](#architecture-diagram)
- [Run with Docker](#run-with-docker)
- [Local Development](#local-development)
- [TODO](#todo)
- [Development Attribution](#development-attribution)
- [Special Notes](#special-notes)

## Description

`live-chat` is a multi-room real-time chat application. It uses browser-session nickname identity instead of a traditional account system, supports persistent messages, and keeps live presence/typing state in memory for fast room updates.

### Room View
The main room screen combines persistent message history with live SSE updates for new messages, online presence, typing state, room activity, and room list changes. The interface includes theme switching, mention toasts, a profile editor for nickname and color, and room-scoped activity popovers.

### Nickname Entry
The entry flow is intentionally lightweight: users choose a nickname, receive a browser-session cookie pair, and are redirected into the Lobby. Nickname ownership is protected against active conflicts, while user profile color and room activity history remain persisted.

### Light Mode
![light-mode](images/live-chat-light-mode.png)

### Dark Mode
![dark-mode](images/live-chat-dark-mode.png)

[Back to top](#top)

## Main Features
- Browser-session nickname identity with collision protection for active users
- Auto-created `Lobby` room plus additional room creation
- Persistent room messages in PostgreSQL with scroll-up pagination for older history
- Room-scoped live updates over SSE for messages, online presence, typing state, activity feed, and room navigation
- User profile editing for nickname and nickname color with propagation to future/live UI
- Room-scoped mentions, including direct user mentions and `@everyone`
- Bottom-right mention toast notifications delivered through a dedicated notification SSE stream
- Online presence cards with relative timestamps and “You” badges
- Per-room activity feed for joins, leaves, rejoins, and nickname changes
- Dark/light theme support with token-driven styling across panels, cards, and feeds

[Back to top](#top)

## Tech Stack
- Frontend/UI: Astro 6 SSR, HTMX 2, Alpine.js, Tailwind CSS v4
- Realtime layer: Server-Sent Events with server-rendered HTML fragments
- Backend/runtime: Astro Node adapter on Node.js 22 and Drizzle ORM
- Runtime: Docker, Docker Compose
- HostOS / Virtualization: Windows 11 / Hyper-V
- Linux Emulation: WSL Ubuntu

[Back to top](#top)

## Data Model
- `rooms`: chat rooms with unique room names, optional descriptions, and audit timestamps
- `messages`: persistent room messages storing nickname, nickname color, body, timestamp, and row type
- `user_profiles`: browser-session keyed nickname/color profile state used for future/live identity rendering
- `room_activity_events`: persistent per-room activity log for joins, leaves, rejoins, and nickname changes

Core runtime flow:
- Claiming a nickname reserves active ownership in memory and upserts the browser-session profile in PostgreSQL
- Joining a room creates or refreshes in-memory presence state and emits updated presence/activity fragments
- Sending a message persists a `messages` row, emits an SSE message fragment, and routes any mentions to the notification stream
- Editing a profile updates the `user_profiles` row and refreshes live room state for active rooms owned by that browser session
- Room activity writes durable `room_activity_events` rows, while presence and typing remain intentionally in-memory and single-process

[Back to top](#top)

## Architecture Diagram
```mermaid
flowchart LR
  U[User / Browser] --> APP[Astro SSR App<br/>HTMX + Alpine]
  APP -->|room SSE / notification SSE| U
  APP -->|messages, profiles, rooms,<br/>activity events| DB[(PostgreSQL 17)]
  APP --> MEM[(In-memory room state)]

  DB --- ROOMS[(rooms)]
  DB --- MSG[(messages)]
  DB --- PROF[(user_profiles)]
  DB --- ACT[(room_activity_events)]

  MEM --- PRES[(presence)]
  MEM --- TYPE[(typing)]
  MEM --- OWN[(nickname owners)]
  MEM --- NOTIFY[(mention event emitter)]

  U -->|nickname claim, room actions,<br/>profile edits, mentions| APP
  APP -->|server-rendered HTML fragments| U
  APP -->|activity + message persistence| DB
  APP -->|fast live room fan-out| MEM
```

[Back to top](#top)

## Run with Docker
1. Copy `.env.example` to `.env` if you want to override defaults:
   ```bash
   cp .env.example .env
   ```
2. Create local Docker secret files and update your `.env` file accordingy:
   ```bash
   mkdir -p <secdir>
   <secdir>/db_name
   echo "XXXXXXXXXXXXXXXXX" > <secdir>/db_name
   echo "XXXXXXXXXXXXXXXXX" > <secdir>/db_user
   echo "XXXXXXXXXXXXXXXXX" > <secdir>/db_password
   cat >> .env << EOF
   DB_NAME=${pwd}/<secdir>/db_name
   DB_USER=${pwd}/<secdir>/db_user
   DB_PASSWORD=${pwd}/<secdir>/db_password
   EOF
   ```
3. Create the volume directory and update your `.env` file accordingy:
   ```bash
   mkdir -p <voldir>
   chown -R 70:70 <voldir>
   chmod -R 700 <voldir>
   cat >> .env << EOF
   DB_VOLUME=${pwd}/<db-vol-dir>
   EOF
   ```
4. Start the stack in the repo root:
   ```bash
   docker compose -f docker-compose.yml --env-file .env up --build --detach
   ```
6. The live chat app will be available at `http://localhost:8083`.
7. Stop the stack from the repo root:
   ```bash
   docker compose -f docker-compose.yml --env-file .env down
   ```

[Back to top](#top)

## Local Development
Local development is centered on the Docker Compose stack.

**Configuration**

- `DB_HOST`, `DB_PORT`: PostgreSQL container host/port values
- `FRONTEND_PORT`: Astro host/container port exposed by Docker Compose
- `HOST`: Astro bind host
- `APP_ORIGIN`: origin-aware app setting for redirects/cookies
- `NICKNAME_COOKIE_NAME`: browser nickname cookie name used by the app runtime
- `DB_UID`, `DB_GID`: uid/gid used for the bind-mounted PostgreSQL volume
- `DB_NAME`, `DB_USER`, `DB_PASSWORD`: secret-file paths consumed by Docker secrets
- `DB_VOLUME`: bind-mounted PostgreSQL data directory

**Main files and services**

- [docker-compose.yml](docker-compose.yml): Docker topology for the Astro app and PostgreSQL
- [docker/](docker): Astro SSR app, Drizzle schema, realtime room logic, migrations, and startup scripts
- [docker/src/lib/server/schema.ts](docker/src/lib/server/schema.ts): PostgreSQL schema definitions for rooms, messages, profiles, and room activity

**Verification**

- Migrations are applied automatically during container startup, so successful startup should include the app becoming available after the database health check
- Manual verification should cover nickname claim, room creation, message send/pagination, mention toasts, profile editing, activity feed updates, theme switching, and presence cleanup

[Back to top](#top)

## TODO
1. Add browser-level automated tests for mentions, activity feed behavior, and theme-driven UI regressions.
2. Revisit the single-process in-memory presence model if the app ever needs multi-instance deployment.

[Back to top](#top)

## Development Attribution
- Principal developer: Codex (GPT-5 coding agent). _// old N00b assisted a bit_
- Collaboration model: iterative prompt-driven development in the local repo with repeated implementation, Docker rebuilds, runtime verification, and UI refinement.

### Prompt Summary (Consolidated)

- Build a browser-hosted session-based multi-room chat app with Astro SSR, HTMX, Alpine, SSE, and PostgreSQL.
- Support nickname claim, room creation, persistent messaging, message pagination, and room navigation.
- Add live online presence and typing indicators with room-scoped fan-out.
- Add room-scoped mentions and bottom-right mention toast notifications.
- Add persistent profile editing for nickname and nickname color.
- Add a room activity feed for joins, leaves, rejoins, and nickname changes.
- Keep Docker Compose as the primary runtime and documentation workflow, including migrations at startup.
- Continue refining the UI for layout, scrolling behavior, popovers, dark/light border treatments, and theme consistency.

[Back to top](#top)

## Special Notes
- Presence, typing, nickname ownership, and notification fan-out are intentionally in-memory and single-process.
- PostgreSQL data is persisted outside the repo through the configured bind-mounted `DB_VOLUME`.
- Container startup waits for PostgreSQL, applies migrations, ensures the `Lobby` exists, and then starts the Astro Node server.

[Back to top](#top)
