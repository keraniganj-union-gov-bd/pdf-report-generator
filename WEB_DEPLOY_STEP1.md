# Step 1 — Web Version

This package is based directly on `free_pdf_report_dev_v59_windows.zip`.

## Preserved
- Existing V59 PDF layout/design
- Existing PDF generation logic
- Existing QR/photo/background behavior
- Existing `V1_<NID>.pdf` filename behavior
- Existing source-PDF parsing

## Added for web deployment
- `requirements.txt` dependencies for a Python/FastAPI deployment
- `render.yaml`
- `run_web_windows.bat` for local browser testing

## Render
Build:
`pip install -r requirements.txt`

Start:
`uvicorn app.main:app --host 0.0.0.0 --port $PORT`

The default Background workflow is planned for the next deployment step:
Admin sets one default background; customers upload only Source PDF.
