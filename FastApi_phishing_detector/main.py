from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
import os
import jinja2

from scanner.url_features import extract_all_url_features
from scanner.nltk_features import extract_nltk_features
from scanner.predictor import predict_url, predict_nltk, get_final_verdict
from scanner.owasp_risk import generate_owasp_report
from database import (
    init_db, save_scan, get_scan_by_id, get_all_scans, 
    get_scan_count, delete_scan, clear_all_scans, search_scans
)
import time


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="Phishing Detection Scanner")

# Initialize database on startup
init_db()

# Use jinja2 directly to avoid starlette/TemplateResponse cache issues
_template_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(BASE_DIR, "templates")),
    autoescape=True,
)


def _render_template(template_name: str, **context) -> str:
    """Render a Jinja2 template with the given context."""
    template = _template_env.get_template(template_name)
    return template.render(**context)


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, url: str = Query(default=None)):
    """Render the home page with URL input form."""
    html = _render_template(
        "index.html", 
        request=request, 
        result=None, 
        error=None,
        history=None, 
        scan_detail=None, 
        active_tab="scan",
        prefill_url=url
    )
    return HTMLResponse(content=html)


@app.post("/scan", response_class=HTMLResponse)
async def scan_url(request: Request, url: str = Form(...)):
    """Scan a URL for phishing indicators using all 3 ML models."""
    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    start_time = time.time()
    error = None

    try:
        # Extract URL features
        url_result = extract_all_url_features(url)

        # Extract NLTK features
        nltk_result = extract_nltk_features(url)

        # Run predictions
        url_predictions = predict_url(url_result["features"])
        nltk_predictions = predict_nltk(nltk_result["features"])

        # Get final verdict
        verdict = get_final_verdict(url_predictions, nltk_predictions)

        scan_time = round(time.time() - start_time, 2)

        # Generate OWASP risk report
        owasp_report = generate_owasp_report(
            url_features=url_result["features"],
            nltk_details=nltk_result["details"],
            verdict=verdict["verdict"],
            confidence=verdict["confidence"],
        )

        result = {
            "url": url,
            "url_features": url_result["features"],
            "url_details": url_result["details"],
            "nltk_features": nltk_result["features"],
            "nltk_details": nltk_result["details"],
            "predictions": url_predictions,
            "nltk_predictions": nltk_predictions,
            "verdict": verdict,
            "scan_time": scan_time,
            "owasp_report": owasp_report,
        }

        # Save to database
        save_scan(result)

        html = _render_template(
            "index.html", 
            request=request, 
            result=result, 
            error=None,
            history=None, 
            scan_detail=None, 
            active_tab="scan",
            prefill_url=None
        )
        return HTMLResponse(content=html)

    except Exception as e:
        error = f"Error scanning URL: {str(e)}"
        html = _render_template(
            "index.html", 
            request=request, 
            result=None, 
            error=error,
            history=None, 
            scan_detail=None, 
            active_tab="scan",
            prefill_url=None
        )
        return HTMLResponse(content=html)


@app.get("/history", response_class=HTMLResponse)
async def history(
    request: Request, 
    page: int = Query(default=1, ge=1),
    search: str = Query(default=None)
):
    """Show scan history list."""
    per_page = 20
    offset = (page - 1) * per_page
    
    if search:
        scans = search_scans(query=search, limit=per_page, offset=offset)
        total = len(scans)
    else:
        scans = get_all_scans(limit=per_page, offset=offset)
        total = get_scan_count()
    
    total_pages = max(1, (total + per_page - 1) // per_page)
    
    html = _render_template(
        "index.html", 
        request=request, 
        result=None, 
        error=None,
        history=scans, 
        scan_detail=None, 
        active_tab="history",
        current_page=page, 
        total_pages=total_pages, 
        total_scans=total,
        search_query=search,
        prefill_url=None
    )
    return HTMLResponse(content=html)


@app.get("/history/{scan_id}", response_class=HTMLResponse)
async def view_scan(request: Request, scan_id: int):
    """View a specific scan result from history."""
    scan = get_scan_by_id(scan_id)
    if scan is None:
        html = _render_template(
            "index.html", 
            request=request, 
            result=None, 
            error="Scan record not found",
            history=None, 
            scan_detail=None, 
            active_tab="history",
            prefill_url=None
        )
        return HTMLResponse(content=html)
    
    html = _render_template(
        "index.html", 
        request=request, 
        result=scan, 
        error=None,
        history=None, 
        scan_detail=True, 
        active_tab="history",
        prefill_url=None
    )
    return HTMLResponse(content=html)


@app.get("/history/{scan_id}/delete", response_class=HTMLResponse)
async def delete_scan_record(request: Request, scan_id: int):
    """Delete a scan record and redirect to history."""
    delete_scan(scan_id)
    return RedirectResponse(url="/history", status_code=303)



