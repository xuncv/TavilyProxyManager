# Tavily Proxy & Management Dashboard

简体中文 | English

A transparent reverse proxy for the Tavily API that aggregates multiple Tavily API Keys into a single **Master Key**. It features a built-in Web UI for managing keys, monitoring usage, and inspecting request logs.

---

## 🚀 Features

- **Transparent Proxy**: Seamlessly forwards requests to `https://api.tavily.com` (supports all endpoints/methods).
- **Master Key Authentication**: Secure access via `Authorization: Bearer <MasterKey>`.
- **Intelligent Key Pooling**:
  - Prioritizes keys with the highest remaining quota.
  - Randomly distributes requests among keys with equal quota to prevent rate limiting.
- **Automatic Failover**: Automatically retries with the next available key upon receiving `401`, `429`, `432`, or `433` errors.
- **MCP Support**: Built-in HTTP MCP (Model Context Protocol) endpoint for easy integration with AI tools (e.g., Claude, VS Code).
- **Comprehensive Dashboard**:
  - **Key Management**: Add, delete, and sync quotas for multiple Tavily keys.
  - **Usage Statistics**: Visualized charts for request volume and quota consumption.
  - **Request Logs**: Detailed logs with filtering and manual cleanup options.
- **Automated Tasks**: Monthly quota resets and periodic log cleaning.
- **Self-Contained**: Single binary deployment with embedded Web UI (Vite + Vue 3 + Naive UI).

---

## 🛠️ Requirements

- **Docker / Docker Compose** (Recommended deployment method, no local environment needed)
- **Go**: `1.23+` & **Node.js**: `20+` (Only for manual builds)

---

## 📦 Quick Deployment (Docker)

Deploy directly using the GHCR image, **no local compilation required**.

### 1. Using Docker Compose (Recommended)

Create a `docker-compose.yml` file:

```yaml
version: "3.8"
services:
  tavily-proxy:
    image: ghcr.io/xuncv/tavilyproxymanager:latest
    container_name: tavily-proxy
    ports:
      - "8080:8080"
    environment:
      - LISTEN_ADDR=:8080
      - DATABASE_PATH=/app/data/proxy.db
      - TAVILY_BASE_URL=https://api.tavily.com
      - UPSTREAM_TIMEOUT=30s
    volumes:
      - ./data:/app/data
      - /etc/localtime:/etc/localtime:ro
    restart: unless-stopped
```

Start the service:

```bash
docker-compose up -d
```

### 2. Using Docker CLI

```bash
docker run -d \
  --name tavily-proxy \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -e DATABASE_PATH=/app/data/proxy.db \
  ghcr.io/xuncv/tavilyproxymanager:latest
```

---

## 🔑 First Run: Obtaining the Master Key

The service automatically generates a random **Master Key** during its **first startup**. This key is required to log into the dashboard and authenticate API calls.

You can retrieve it by checking the container logs:

```bash
docker logs tavily-proxy 2>&1 | grep "master key"
```

**Log Example:**
`level=INFO msg="no master key found, generated a new one" key=your_generated_master_key_here`

> **Tip**: It is highly recommended to save this key in a secure location after your first login.

---

## 🛠️ Local Development & Manual Building

If you need to modify the code and build it yourself:

1.  **Start Backend**:
    ```bash
    go run ./server
    ```
2.  **Start Frontend**:
    ```bash
    cd web && npm install && npm run dev
    ```

**Manual Binary Build**:

- **Windows**: `.\scripts\build_all.ps1`
- **Linux/macOS**: `./scripts/build_all.sh`

**Local Image Build with Dockerfile**:

```bash
docker build -t my-tavily-proxy .
```

---

## 📖 Usage Guide

### REST API Proxy

Call the proxy exactly as you would the official Tavily API, simply replacing the API base URL and using your **Master Key**:

```bash
curl -X POST "http://localhost:8080/search" \
  -H "Authorization: Bearer <MASTER_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"query": "Latest AI trends", "search_depth": "basic"}'
```

**Compatibility Notes**:

- Supports `{"api_key": "<MASTER_KEY>"}` or `{"apiKey": "<MASTER_KEY>"}` in JSON bodies.
- Supports the `api_key=<MASTER_KEY>` GET parameter.

### MCP (Model Context Protocol)

The server provides an HTTP MCP endpoint at `http://localhost:8080/mcp`.

#### VS Code Configuration (with mcp-remote)

```json
{
  "servers": {
    "tavily-proxy": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://localhost:8080/mcp",
        "--header",
        "Authorization: Bearer YOUR_MASTER_KEY"
      ]
    }
  }
}
```

---

## ⚙️ Configuration (Environment Variables)

| Variable           | Description              | Default                  |
| :----------------- | :----------------------- | :----------------------- |
| `LISTEN_ADDR`      | Server listening address | `:8080`                  |
| `DATABASE_PATH`    | Path to SQLite database  | `/app/data/proxy.db`     |
| `TAVILY_BASE_URL`  | Upstream Tavily API URL  | `https://api.tavily.com` |
| `UPSTREAM_TIMEOUT` | Upstream request timeout | `150s`                   |

---

## 📄 License

This project is licensed under the MIT License.
