# Human Web Dashboard

Owns responsive phone/Mac/desktop viewing and owner configuration through the Main Server. `src/` separates dashboard, access, recordings, timeline, setup, and shared UI responsibilities.

Private-network reachability and ServerSentinel invitation/permission are independent gates. `live:view` and `recordings:view` are independent; historical events/timeline require `recordings:view`. The server enforces every permission, including playback assets.

Browsers are viewers in MVP: no browser/iPhone camera capture, audio controls, direct agent viewing, or non-owner download/export feature. Browser playback does not prevent screen recording/client capture. Do not claim network concealment with unchanged Tailnet policy or show unreliable detection as a trustworthy negative.
