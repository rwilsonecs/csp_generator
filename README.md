#  CSP Generator & Auditor

This tool crawls a target website, identifies externally loaded resources (fonts, scripts, stylesheets, images, etc.), and generates:

- A valid **Content-Security-Policy** (CSP) header  
- A production-ready `web.config` entry for **IIS**  
- A JSON representation of the CSP for audits or automation  

---

##  Features

- ✅ Spiders up to N pages  
- ✅ Extracts external domains by resource type  
- ✅ Categorizes resources into CSP directives  
- ✅ Generates both `web.config` and `JSON` output formats  
- ✅ CLI-driven with argument parsing  

---

## Installation

```
git clone https://github.com/your-org/csp-generator
cd csp-generator
pip install -r requirements.txt
```

> **Dependencies:**  
> - `requests`  
> - `beautifulsoup4`  

Install manually with:

```
pip install requests beautifulsoup4
```

---

## Usage

```
python3 generate_csp.py --url https://your-website.com --output-dir ./output --max-pages 50
```

**Arguments:**

| Flag           | Description                                      |
|----------------|--------------------------------------------------|
| `--url`        | The base URL to start crawling from               |
| `--output-dir` | Where to save the generated CSP files             |
| `--max-pages`  | Maximum number of pages to spider (default: 25)   |

---

## Output Files

Inside your `--output-dir`, you will get:

### 🔸 `csp_policy.json`

A structured breakdown of allowed domains by CSP directive:

```
{
  "script-src": ["cdnjs.cloudflare.com", "fonts.googleapis.com", "'self'"],
  "style-src": ["fonts.googleapis.com", "'self'"],
  "font-src": ["fonts.gstatic.com", "'self'"],
  "img-src": ["imgur.com", "'self'"]
}
```

---

### 🔸 `web.config`

This can be dropped directly into an IIS deployment:

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="script-src 'self' cdnjs.cloudflare.com; style-src 'self' fonts.googleapis.com; font-src 'self' fonts.gstatic.com;" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
```

---

## How to Implement the CSP Header

### 📍 For IIS (`web.config`)

Paste the `<customHeaders>` section into your server's main `web.config` file, usually under:

```
<system.webServer><httpProtocol>...</httpProtocol></system.webServer>
```

Restart IIS or recycle the app pool if needed.

---

### For Apache/Nginx

Instead of `web.config`, use this format in headers:

```
Content-Security-Policy: script-src 'self' cdn.example.com; style-src 'self' fonts.googleapis.com;
```

Apply this in:

- Apache: via `.htaccess` or `Header set` directive  
- Nginx: inside `add_header` in your `server` block  

---

## Best Practices

- Use the JSON output for security audits or CSP reports.  
- Deploy CSP headers in **Report-Only mode** first to prevent breakage:  

```
Content-Security-Policy-Report-Only: ...
```

- Monitor CSP violations in the browser console or via `report-uri`.  

---

## Contributions

PRs are welcome — especially for:
- Auto-detecting `unsafe-inline` or nonce-based policies  
- CSP diffing / baselining  

---

## Author

ECS Red Team
Licensed under MIT

