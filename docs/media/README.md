# Media assets

Screenshots and demo media referenced from the top-level [README](../../README.md).

## Screenshots

Commit PNGs here and uncomment the embeds in the README's **Trace dashboard** section.
Expected filenames (rename the embeds if you change these):

| File | Capture |
|------|---------|
| `dashboard-trace.png` | Trace Viewer — chronological tool/DAIR/reason/finding stream |
| `dashboard-chain.png` | Investigation Chain — finding lineage |
| `dashboard-graph.png` | Investigation Graph — causal DAG |

Keep individual images reasonable (PNG, ideally < ~500 KB each) so the repo stays light.
A short looping GIF (e.g. `dashboard.gif`) is great for an inline preview.

## Demo video

**Do not commit the full-length video here** — a multi-MB/large MP4 bloats git history
permanently. Instead:

1. **Host it** on Devpost (required for the submission anyway) and/or YouTube, and link
   it from the README's `📹 Demo video` line.
2. For an inline GitHub preview, either:
   - drop a short, low-res **GIF** (`docs/media/demo.gif`) and embed it, or
   - attach the MP4 to a **GitHub Release** / drag it into a PR or issue to get a
     `github.com/.../assets/...` CDN URL that renders inline — without it living in the
     working tree.
3. If the raw MP4 truly must live in the repo, use **Git LFS** (`git lfs track "*.mp4"`).
