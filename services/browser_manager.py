import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import Any

from playwright.async_api import Browser, async_playwright

from .log_filter import logger

MAX_PLAYWRIGHT_INSTANCES = int(os.getenv("MAX_PLAYWRIGHT_INSTANCES", "3"))
PLAYWRIGHT_SLOT_TIMEOUT = int(os.getenv("PLAYWRIGHT_SLOT_TIMEOUT", "30"))
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "30"))
MAX_SESSIONS = int(os.getenv("MAX_SESSIONS", "100"))

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class PlaywrightManager:
    """
    Manages Playwright browser instance, context pool, and anti-bot evasion settings.
    """

    def __init__(self):
        self.playwright = None
        self.browser: Browser | None = None
        self.slots_free = MAX_PLAYWRIGHT_INSTANCES
        self._slots_lock = asyncio.Lock()
        self._init_lock = asyncio.Lock()

    async def initialize(self):
        async with self._init_lock:
            if self.playwright is None:
                logger.info("Initializing global Playwright Chromium instance...")
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-accelerated-2d-canvas",
                        "--no-first-run",
                        "--no-zygote",
                        "--disable-gpu",
                    ],
                )

    async def start(self):
        await self.initialize()

    async def stop(self):
        await self.close()

    async def close(self):
        async with self._init_lock:
            if self.browser:
                logger.info("Closing Playwright Chromium browser...")
                await self.browser.close()
                self.browser = None
            if self.playwright:
                await self.playwright.stop()
                self.playwright = None

    @asynccontextmanager
    async def acquire_context(
        self,
        proxy_url: str | None = None,
        user_headers: dict | None = None,
        stealth: bool = False,
    ):
        await self.initialize()

        start_wait = time.monotonic()
        async with self._slots_lock:
            if self.slots_free <= 0:
                logger.warning(
                    "Max Playwright instances reached. Waiting for available slot..."
                )
            while self.slots_free <= 0:
                if time.monotonic() - start_wait > PLAYWRIGHT_SLOT_TIMEOUT:
                    logger.error(
                        f"Playwright slot acquisition timed out after {PLAYWRIGHT_SLOT_TIMEOUT}s."
                    )
                    raise TimeoutError(
                        f"All Playwright browser slots are occupied. Acquisition timed out after {PLAYWRIGHT_SLOT_TIMEOUT}s."
                    )
                await asyncio.sleep(0.1)
            self.slots_free -= 1
            _free = self.slots_free
        logger.info(f"Acquired Playwright slot. Free slots: {_free}")

        context = None
        try:
            if not self.browser:
                raise RuntimeError("Playwright browser is not initialized.")

            context_args: dict[str, Any] = {}
            if proxy_url:
                context_args["proxy"] = {"server": proxy_url}

            # Evasion: Use standard desktop browser User-Agent
            context_args["user_agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

            context_args.update(
                {
                    "viewport": {
                        "width": 1920 if stealth else 1280,
                        "height": 1080 if stealth else 720,
                    },
                    "device_scale_factor": 1,
                    "is_mobile": False,
                    "has_touch": False,
                    "locale": "en-US",
                    "timezone_id": "America/New_York",
                }
            )

            context = await self.browser.new_context(**context_args)

            # Evasion: Remove navigator.webdriver property to bypass simple bot checks
            await context.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )

            if stealth:
                # Mock WebGL params
                webgl_script = """
                const getParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(parameter) {
                    // UNMASKED_VENDOR_WEBGL
                    if (parameter === 37445) {
                        return 'Intel Open Source Technology Center';
                    }
                    // UNMASKED_RENDERER_WEBGL
                    if (parameter === 37446) {
                        return 'Mesa DRI Intel(R) HD Graphics 620 (Kaby Lake GT2)';
                    }
                    return getParameter.apply(this, arguments);
                };
                """
                await context.add_init_script(webgl_script)

                # Mock plugins, languages, hardwareConcurrency
                nav_script = """
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5]
                });
                Object.defineProperty(navigator, 'hardwareConcurrency', {
                    get: () => 8
                });
                """
                await context.add_init_script(nav_script)

            if user_headers:
                await context.set_extra_http_headers(user_headers)

            yield context
        finally:
            if context:
                try:
                    await context.close()
                except Exception as e:
                    logger.error(f"Error closing playwright context: {e}")
            async with self._slots_lock:
                self.slots_free += 1
                _free = self.slots_free
            logger.info(f"Released Playwright slot. Free slots: {_free}")


playwright_mgr = PlaywrightManager()
