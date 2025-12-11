"""
Testy konfiguracji bezpieczeństwa i ustawień środowiskowych.
"""
from app import create_app
from config import TestingConfig, ProductionConfig
import pytest


def test_session_timeout_configured():
    """Weryfikuj że PERMANENT_SESSION_LIFETIME ustawione na 8h"""
    app = create_app()
    from datetime import timedelta
    assert app.config['PERMANENT_SESSION_LIFETIME'] == timedelta(hours=8)


def test_production_config_forces_secure_cookies():
    """W produkcji SESSION_COOKIE_SECURE powinno być True"""
    assert ProductionConfig.SESSION_COOKIE_SECURE is True


def test_production_config_has_samesite_lax():
    """SameSite=Lax zabezpiecza przed CSRF przy nawigacji cross-site"""
    from config import BaseConfig
    assert BaseConfig.SESSION_COOKIE_SAMESITE == 'Lax'


def test_csrf_enabled_in_dev():
    """CSRF powinno być włączone domyślnie (testing ma wyłączone dla wygody)"""
    from config import DevelopmentConfig
    assert DevelopmentConfig.WTF_CSRF_ENABLED is True


def test_testing_config_uses_memory_db():
    """Testy używają SQLite in-memory dla szybkości"""
    assert TestingConfig.SQLALCHEMY_DATABASE_URI == "sqlite:///:memory:"


def test_csp_configured():
    """CSP powinno być generowane dynamicznie z nonce per-request"""
    from app import create_app
    from config import TestingConfig
    
    app = create_app()
    app.config.from_object(TestingConfig)
    client = app.test_client()
    
    # Pobierz nagłówek CSP z rzeczywistego żądania
    resp = client.get('/')
    csp = resp.headers.get('Content-Security-Policy', '')
    
    # Sprawdź że CSP zawiera oczekiwane dyrektywy
    assert "'none'" in csp  # object-src 'none', frame-ancestors 'none'
    assert "'self'" in csp  # script-src 'self'
    assert "'nonce-" in csp  # nonce per-request
    
    # Sprawdź że NIE zawiera unsafe-inline (dangerous)
    assert "'unsafe-inline'" not in csp

