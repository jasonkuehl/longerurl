# Make A Longer Link

A completely unnecessary URL lengthening service. Because sometimes URLs just aren't long enough.

## What is this?

While everyone else is busy shortening URLs, we're doing the exact opposite. Enter a URL, choose your desired absurdity level, and get a gloriously long URL that redirects to the original.

## Features

- 🔗 Convert any URL into an absurdly long one
- 📏 Adjustable length (500 to 8000 characters)
- 🎲 Deterministic dial-up modem sound generation
- 📋 One-click copy to clipboard
- 📊 Stats showing how much longer your URL is now
- 🐳 Docker ready
- ♻️ **Stateless** - no database needed, links survive restarts

## Quick Start

### With Docker Compose

```bash
docker compose up -d
```

Then visit http://localhost:60320

### Without Docker

```bash
go build -o makealongerlink
./makealongerlink
```

## How It Works

1. Enter a URL
2. Choose how ridiculously long you want it (1-10 scale)
3. Click "MAKE IT LONGER!"
4. Share your gloriously long URL with the world

## API

### POST /api/lengthen

Create a longer URL.

**Request:**
```json
{
  "url": "https://example.com",
  "length": 5
}
```

**Response:**
```json
{
  "original": "https://example.com",
  "long": "http://localhost:60320/r/a1b2c3d4e5...",
  "length": 900
}
```

### GET /r/{slug}

Redirects to the original URL.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT     | 60320   | Server port |

## Note

This service is **stateless** - URLs are deterministically generated based on the input URL. The same input will always produce the same long URL, so links work even after server restarts. No database required!

## Why?

Why not?

## License

MIT - Do whatever you want with this.
