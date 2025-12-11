from app import create_app
from config import TestingConfig


def test_security_headers_present_on_api():
    app = create_app()
    app.config.from_object(TestingConfig)
    client = app.test_client()
    resp = client.get('/api/health')
    # Basic security headers asserted
    assert resp.headers.get('Content-Security-Policy') is not None
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    # Request ID propagation
    assert resp.headers.get('X-Request-ID') is not None


def test_security_headers_present_on_html():
    app = create_app()
    app.config.from_object(TestingConfig)
    client = app.test_client()
    resp = client.get('/')
    assert resp.status_code in (200, 302)  # 302 if login redirect
    # Headers present as in API
    assert resp.headers.get('Content-Security-Policy') is not None
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'


def test_csp_contains_nonce():
    """CSP header should contain nonce, not unsafe-inline for script-src and style-src"""
    app = create_app()
    app.config.from_object(TestingConfig)
    client = app.test_client()
    
    # Request HTML page to trigger CSP header generation
    resp = client.get('/')
    csp = resp.headers.get('Content-Security-Policy', '')
    
    # Should have nonce for script-src
    assert "'nonce-" in csp, f"CSP should contain nonce in script-src, got: {csp}"
    
    # Should NOT have unsafe-inline in script-src (harmful for security)
    assert "'unsafe-inline'" not in csp, f"CSP should NOT contain unsafe-inline, got: {csp}"
    
    # Verify it's in both script-src and style-src
    script_src_has_nonce = "script-src 'self' 'nonce-" in csp
    style_src_has_nonce = "style-src 'self' 'nonce-" in csp
    assert script_src_has_nonce, f"script-src missing nonce in: {csp}"
    assert style_src_has_nonce, f"style-src missing nonce in: {csp}"

