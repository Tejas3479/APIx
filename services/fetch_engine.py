import asyncio
import base64
import random
import re
from urllib.parse import urljoin

from curl_cffi.requests import AsyncSession as CurlSession

from captcha_solver import CaptchaDetector
from database import ProxyManager

from .browser_manager import PlaywrightManager
from .content import process_content
from .log_filter import logger, sanitize_proxy_url, sanitize_url
from .robots_checker import RobotsTxtChecker
from .ssrf import is_ssrf_safe


async def run_fetch(
    url: str,
    method: str,
    headers: dict,
    cookies: dict,
    body: str | None,
    json_body: dict | None,
    session: dict | None,
    render_js: bool,
    scroll: bool,
    proxy_url: str | None,
    max_retries: int,
    timeout: int,
    impersonate: str,
    playwright_mgr: "PlaywrightManager",
    output_format: str,
    strip_links: bool,
    llm_api_key: str | None,
    llm_provider: str,
    json_schema: dict | None,
    wait_for_selector: str | None = None,
    wait_timeout: int = 30,
    css_selector: str | None = None,
    llm_model: str | None = None,
    actions: list | None = None,
    screenshot: bool = False,
    screenshot_format: str = "png",
    extraction_prompt: str | None = None,
    wait_until: str = "networkidle",
    stealth: bool = False,
) -> dict:
    """
    Returns dict with keys:
      final_url, status_code, raw_html, content, retries_used, error, error_message, screenshot, timing
    """
    import time as _time

    _t0 = _time.monotonic()
    # 1. SSRF Safety Check (async-safe DNS resolution)
    if not await is_ssrf_safe(url):
        logger.warning(f"Blocking request to restricted URL: {url}")
        return {
            "final_url": url,
            "status_code": 403,
            "content": "Forbidden: Target URL resolves to a restricted local or private address.",
            "raw_html": "",
            "retries_used": 0,
            "error": "forbidden_address",
            "error_message": f"URL {url} resolves to a restricted local or private address.",
            "screenshot": None,
            "timing": None,
        }

    # 1b. Robots.txt Compliance Check
    if not await RobotsTxtChecker.is_allowed(url):
        logger.warning(f"Blocking request disallowed by robots.txt: {url}")
        return {
            "final_url": url,
            "status_code": 403,
            "content": "Forbidden: Target URL disallowed by site robots.txt policy.",
            "raw_html": "",
            "retries_used": 0,
            "error": "robots_txt_disallowed",
            "error_message": f"Scraping path disallowed by site robots.txt policy for {url}.",
            "screenshot": None,
            "timing": None,
        }
    _t_security = _time.monotonic()

    # 2. Parse Proxy Pool (handles comma, newline, and CRLF delimiters)
    proxies_list = []
    if proxy_url:
        proxies_list = [
            p.strip() for p in re.split(r"[,\r\n]+", proxy_url) if p.strip()
        ]

    last_status = 0
    final_url = url
    status_code = 0
    raw_html = ""
    screenshot_data_url = None

    all_cookies = {}
    if session:
        all_cookies.update(cookies)
        all_cookies.update(session["cookies"])
    else:
        all_cookies.update(cookies)

    for attempt in range(max_retries + 1):
        # 3. Rotate Proxy
        current_proxy = None
        if proxies_list:
            current_proxy = proxies_list[attempt % len(proxies_list)]
            logger.info(f"Using rotated proxy: {current_proxy}")

        try:
            logger.info(
                f"Fetch attempt {attempt + 1}/{max_retries + 1} for URL: {url} (JS-rendering: {render_js})"
            )
            if not render_js:
                # CURL PATH
                curl_session = None
                if session:
                    if session["curl_session"] is None:
                        session["curl_session"] = CurlSession(impersonate=impersonate)
                    curl_session = session["curl_session"]
                else:
                    curl_session = CurlSession(impersonate=impersonate)

                kwargs = {
                    "headers": headers,
                    "cookies": all_cookies,
                    "timeout": timeout,
                    "allow_redirects": False,
                }
                if current_proxy:
                    kwargs["proxies"] = {"https": current_proxy, "http": current_proxy}

                if json_body is not None:
                    kwargs["json"] = json_body
                elif body is not None:
                    kwargs["content"] = body.encode()

                current_url = str(url)
                redirects = 0
                while redirects < 10:
                    resp = await curl_session.request(method, current_url, **kwargs)
                    if (
                        resp.status_code in (301, 302, 303, 307, 308)
                        and "Location" in resp.headers
                    ):
                        next_url = urljoin(current_url, resp.headers["Location"])
                        if not await is_ssrf_safe(next_url):
                            raise ValueError(
                                "SSRF restricted address detected in redirect hop"
                            )
                        current_url = next_url
                        redirects += 1
                    else:
                        break

                _t_connect = _time.monotonic()  # first response received
                final_url = str(resp.url)
                status_code = resp.status_code
                raw_html = resp.text
                _t_ttfb = _time.monotonic()  # content fully read
                last_status = status_code

                resp_cookies_dict = dict(resp.cookies)
                all_cookies.update(resp_cookies_dict)
                if session:
                    session["cookies"].update(resp_cookies_dict)

            else:
                # PLAYWRIGHT PATH
                async with playwright_mgr.acquire_context(
                    current_proxy, headers, stealth=stealth
                ) as context:

                    async def route_interceptor(route):
                        req_url = route.request.url
                        if (
                            route.request.resource_type == "document"
                            and not await is_ssrf_safe(req_url)
                        ):
                            await route.abort("blockedbyclient")
                            return
                        await route.continue_()

                    await context.route("**/*", route_interceptor)

                    page = None
                    try:
                        await context.add_cookies(
                            [
                                {"name": k, "value": v, "url": str(url)}
                                for k, v in all_cookies.items()
                            ]
                        )
                        page = await context.new_page()
                        response = None
                        try:
                            response = await page.goto(
                                str(url), wait_until=wait_until, timeout=timeout * 1000
                            )
                            _t_connect = _time.monotonic()  # page navigation complete
                        except Exception as goto_err:
                            _t_connect = _time.monotonic()
                            if "timeout" in str(goto_err).lower():
                                logger.warning(
                                    f"Navigation to {url} timed out (wait_until={wait_until}). Continuing with partially loaded page content."
                                )
                            else:
                                raise
                        status_code = response.status if response else 200
                        last_status = status_code
                        final_url = page.url
                        _t_ttfb = _time.monotonic()  # DOM available

                        # Captcha & Anti-Bot Solving hook
                        try:
                            solved = await CaptchaDetector.detect_and_solve(page)
                            if solved:
                                logger.info(
                                    f"Captcha challenge on {url} was successfully solved!"
                                )
                        except Exception as cap_err:
                            logger.warning(
                                f"Captcha solving error for {url}: {cap_err}"
                            )

                        # Custom Actions processor
                        if actions:
                            logger.info(
                                f"Processing {len(actions)} custom browser actions..."
                            )
                            for action in actions:
                                # Handle both object attributes and dict get (in case of dict deserialization)
                                act_type = (
                                    action.type
                                    if hasattr(action, "type")
                                    else action.get("type")
                                )
                                act_selector = (
                                    action.selector
                                    if hasattr(action, "selector")
                                    else action.get("selector")
                                )
                                act_value = (
                                    action.value
                                    if hasattr(action, "value")
                                    else action.get("value")
                                )
                                act_duration = (
                                    action.duration
                                    if hasattr(action, "duration")
                                    else action.get("duration")
                                )

                                try:
                                    if act_type == "click" and act_selector:
                                        logger.info(f"Action Click: {act_selector}")
                                        await page.click(
                                            act_selector,
                                            timeout=5000,
                                            no_wait_after=True,
                                        )
                                    elif act_type == "fill" and act_selector:
                                        is_sensitive = any(
                                            k in act_selector.lower()
                                            for k in [
                                                "pass",
                                                "secret",
                                                "token",
                                                "key",
                                                "auth",
                                                "cred",
                                            ]
                                        )
                                        log_val = (
                                            "***REDACTED***"
                                            if is_sensitive
                                            else (act_value or "")
                                        )
                                        logger.info(
                                            f"Action Fill: {act_selector} with '{log_val}'"
                                        )
                                        await page.fill(
                                            act_selector, act_value or "", timeout=5000
                                        )
                                    elif act_type == "wait":
                                        duration_s = act_duration or 1
                                        logger.info(f"Action Wait: {duration_s}s")
                                        await page.wait_for_timeout(duration_s * 1000)
                                    elif act_type == "scroll":
                                        if act_selector:
                                            logger.info(
                                                f"Action Scroll to element: {act_selector}"
                                            )
                                            await page.locator(
                                                act_selector
                                            ).scroll_into_view_if_needed(timeout=5000)
                                        else:
                                            logger.info("Action Scroll down")
                                            await page.evaluate(
                                                "window.scrollBy(0, window.innerHeight)"
                                            )
                                            await page.wait_for_timeout(500)
                                    elif act_type == "hover" and act_selector:
                                        logger.info(f"Action Hover: {act_selector}")
                                        await page.hover(act_selector, timeout=5000)
                                    elif act_type == "press" and act_selector:
                                        is_sensitive = any(
                                            k in act_selector.lower()
                                            for k in [
                                                "pass",
                                                "secret",
                                                "token",
                                                "key",
                                                "auth",
                                                "cred",
                                            ]
                                        )
                                        log_key = (
                                            "***REDACTED***"
                                            if is_sensitive
                                            else (act_value or "Enter")
                                        )
                                        logger.info(
                                            f"Action Press Key '{log_key}' on {act_selector}"
                                        )
                                        await page.press(
                                            act_selector,
                                            act_value or "Enter",
                                            timeout=5000,
                                            no_wait_after=True,
                                        )
                                except Exception as action_err:
                                    logger.error(
                                        f"Action {act_type} failed: {action_err}"
                                    )

                            try:
                                # Wait for any navigations triggered by actions to load
                                await page.wait_for_load_state("load", timeout=5000)
                            except Exception as load_err:
                                logger.warning(
                                    f"Wait for load state after actions timed out/failed: {load_err}"
                                )

                        if wait_for_selector:
                            logger.info(
                                f"Waiting for selector '{wait_for_selector}' (timeout: {wait_timeout}s)"
                            )
                            await page.wait_for_selector(
                                wait_for_selector, timeout=wait_timeout * 1000
                            )

                        if scroll:
                            logger.info(
                                "Scrolling down page to trigger lazy loading..."
                            )
                            for _ in range(10):
                                prev_height = await page.evaluate(
                                    "document.body.scrollHeight"
                                )
                                await page.evaluate(
                                    "window.scrollBy(0, window.innerHeight)"
                                )
                                await page.wait_for_timeout(500)
                                new_height = await page.evaluate(
                                    "document.body.scrollHeight"
                                )
                                curr_y = await page.evaluate(
                                    "window.scrollY + window.innerHeight"
                                )
                                if curr_y >= new_height or new_height == prev_height:
                                    break
                            await page.wait_for_timeout(1000)

                        try:
                            raw_html = await page.content()
                        except Exception as content_err:
                            logger.warning(
                                f"Failed to get page content: {content_err}. Waiting for networkidle and retrying..."
                            )
                            try:
                                await page.wait_for_load_state(
                                    "networkidle", timeout=2000
                                )
                            except Exception:
                                pass
                            try:
                                raw_html = await page.content()
                            except Exception as content_err_retry:
                                logger.error(
                                    f"Failed to get page content on retry: {content_err_retry}"
                                )
                                raw_html = "<html><body>Failed to retrieve content due to active navigation.</body></html>"

                        final_url = page.url

                        if screenshot:
                            try:
                                logger.info(
                                    f"Capturing screenshot in format: {screenshot_format}"
                                )
                                s_bytes = await page.screenshot(
                                    type=screenshot_format, full_page=True
                                )
                                screenshot_data_url = f"data:image/{screenshot_format};base64,{base64.b64encode(s_bytes).decode('utf-8')}"
                            except Exception as s_err:
                                logger.error(f"Screenshot capture failed: {s_err}")

                        new_pw_cookies = await context.cookies()

                        pw_cookies_dict = {
                            c["name"]: c["value"] for c in new_pw_cookies
                        }
                        all_cookies.update(pw_cookies_dict)
                        if session:
                            session["cookies"].update(pw_cookies_dict)
                    finally:
                        if page:
                            try:
                                await page.close()
                            except Exception:
                                pass

            if current_proxy:
                if status_code in (429, 500, 502, 503, 504):
                    await ProxyManager.report_failure(current_proxy)
                else:
                    await ProxyManager.report_success(current_proxy)

            if status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                wait = 1.0 * (2**attempt) + random.uniform(0, 1)
                logger.warning(
                    f"Fetch failed with status {status_code}. Retrying in {wait:.2f}s..."
                )
                await asyncio.sleep(wait)
                continue
            break

        except Exception as e:
            if current_proxy:
                await ProxyManager.report_failure(current_proxy)

            e_str = str(e)
            err_type = type(e).__name__

            # Specific Error Classification
            if current_proxy and any(
                k in e_str.lower() or k in err_type.lower()
                for k in ["proxy", "tunnel", "socks", "407"]
            ):
                error_code = "proxy_error"
                error_msg = f"Proxy connection failed for '{sanitize_proxy_url(current_proxy)}': {e_str}"
            elif render_js and any(
                k in e_str.lower() or k in err_type.lower()
                for k in ["playwright", "browser", "chromium", "executable", "context"]
            ):
                error_code = "browser_engine_error"
                error_msg = f"Playwright browser engine error: {e_str}"
            elif any(
                k in e_str.lower() or k in err_type.lower()
                for k in ["timeout", "timed out", "navigation timeout"]
            ):
                error_code = "request_timeout"
                error_msg = f"Request to target URL timed out after {timeout} seconds."
            elif any(
                k in e_str.lower() or k in err_type.lower()
                for k in [
                    "getaddrinfo",
                    "gaierror",
                    "nameresolution",
                    "dns",
                    "servname",
                ]
            ):
                error_code = "dns_resolution_failed"
                error_msg = (
                    f"Could not resolve host domain for URL '{sanitize_url(url)}'."
                )
            elif any(
                k in e_str.lower() or k in err_type.lower()
                for k in ["ssl", "certificate", "cert", "handshake"]
            ):
                error_code = "ssl_handshake_failed"
                error_msg = (
                    f"SSL/TLS handshake failed for '{sanitize_url(url)}': {e_str}"
                )
            else:
                error_code = "fetch_failed"
                error_msg = f"Fetch failed: {e_str}"

            if attempt < max_retries:
                wait = 1.0 * (2**attempt) + random.uniform(0, 1)
                logger.warning(
                    f"Fetch attempt {attempt + 1} failed ({error_code}). Retrying in {wait:.2f}s..."
                )
                await asyncio.sleep(wait)
            else:
                logger.error(
                    f"Max retries exceeded for URL {sanitize_url(url)}. Last error [{error_code}]: {error_msg}"
                )
                return {
                    "error": error_code,
                    "error_message": error_msg,
                    "last_status": last_status,
                    "retries_used": attempt,
                    "final_url": final_url,
                    "status_code": status_code or 502,
                    "content": None,
                    "raw_html": "",
                    "screenshot": None,
                    "timing": None,
                }

    content = await process_content(
        html=raw_html,
        output_format=output_format,
        base_url=final_url,
        strip_links=strip_links,
        llm_api_key=llm_api_key,
        llm_provider=llm_provider,
        json_schema=json_schema,
        css_selector=css_selector,
        llm_model=llm_model,
        extraction_prompt=extraction_prompt,
    )

    _t_done = _time.monotonic()

    # Build timing breakdown (all values in ms)
    _security_ms = int((_t_security - _t0) * 1000)
    _tc = getattr(
        run_fetch, "_t_connect", None
    )  # may not exist if error before connect
    _connect_ms = (
        max(0, int((_t_connect - _t_security) * 1000)) if "_t_connect" in dir() else 0
    )
    _ttfb_ms = (
        max(0, int((_t_ttfb - _t_connect) * 1000))
        if "_t_ttfb" in dir() and "_t_connect" in dir()
        else 0
    )
    _transfer_ms = max(
        0, int((_t_done - (_t_ttfb if "_t_ttfb" in dir() else _t_security)) * 1000)
    )

    return {
        "final_url": final_url,
        "status_code": status_code,
        "content": content,
        "raw_html": raw_html,
        "retries_used": attempt,
        "error": None,
        "error_message": None,
        "screenshot": screenshot_data_url,
        "timing": {
            "security_ms": _security_ms,
            "connect_ms": _connect_ms,
            "ttfb_ms": _ttfb_ms,
            "transfer_ms": _transfer_ms,
            "total_ms": int((_t_done - _t0) * 1000),
        },
    }
