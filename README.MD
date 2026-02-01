# ALU Regex Data Extraction — JamesKanneh

Simple Python tool that extracts emails, URLs, phone numbers and 16-digit credit cards from raw text and writes results to `output.json`.

## Quick start

1. Ensure Python 3.7+ is installed.
2. Run:
```bash
python3 "Data extractor.py"
```

## Files
- `Data extractor.py` — main program
- `sample_input.txt` — example input
- `output.json` — generated output

## Output (example)
```json
{
  "status": "SUCCESS",
  "emails": ["u***r@example.com"],
  "urls": ["https://www.example.com"],
  "phones": ["(555) 123-4567"],
  "cards": ["****-****-****-3456"]
}
```

.
