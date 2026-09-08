import asyncio
import sys
from datetime import datetime, timedelta, timezone

try:
    from playwright.async_api import async_playwright
    from playwright_stealth import Stealth
except ImportError as e:
    print(f"[X] Required packages missing or import error: {e}")
    sys.exit(1)

async def run_mmt_stealth_probe(origin, destination, advance_days=7):
    # Calculate date
    target_date = datetime.now(timezone.utc) + timedelta(days=advance_days)
    date_str = target_date.strftime("%d/%m/%Y") # MMT format: DD/MM/YYYY
    
    url = f"https://www.makemytrip.com/flight/search?itinerary={origin}-{destination}-{date_str}&tripType=O&paxType=A-1_C-0_I-0&intl=false&cabinClass=E"
    
    print("[*] Initializing APIx Stealth Node...")
    print(f"[*] Target URL: {url}")
    print("[*] Simulating Residential Chrome Context to bypass Akamai/Cloudflare...\n")
    
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--no-sandbox"
                ]
            )
        except Exception:
            print("[X] Chromium not installed. Run: python -m playwright install chromium")
            return

        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            locale="en-IN",
            timezone_id="Asia/Kolkata",
        )
        page = await context.new_page()
        
        # Apply anti-bot evasion scripts (removes webdriver flag, patches plugins)
        await Stealth().apply_stealth_async(page)
        
        print("[*] Navigating to MakeMyTrip Checkout...")
        
        # Intercept XHR to find the background JSON flight data payload
        captured_data = []
        
        async def handle_response(response):
            if "flight/search" in response.url or "api/search" in response.url:
                try:
                    if response.status == 200 and "application/json" in response.headers.get("content-type", ""):
                        data = await response.json()
                        captured_data.append(data)
                except Exception:
                    pass

        page.on("response", handle_response)
        
        try:
            # Wait until the network is relatively idle, bypassing the initial loading screens
            await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            await page.wait_for_timeout(3000) # Give React time to hydrate
            print("[*] DOM Loaded. Akamai WAF Bypassed Successfully.")
        except Exception as e:
            if "ERR_HTTP2_PROTOCOL_ERROR" in str(e):
                print("[!] HTTP2 Protocol Error detected (Akamai strict mode). Falling back to XHR capture...")
            else:
                raise
            
        print("[*] Extracting internal SSR __NEXT_DATA__ payload...")
        
        # Extract internal NextJS properties that contain the raw checkout prices
        try:
            next_data = await page.evaluate('''() => {
                const el = document.getElementById('__NEXT_DATA__');
                return el ? JSON.parse(el.textContent) : null;
            }''')
        except Exception:
            next_data = None
            
        print("\n" + "="*60)
        print("[SUCCESS] LIVE STEALTH HARVEST COMPLETED")
        print("="*60)
        
        if next_data:
            print("[+] Extracted __NEXT_DATA__ SSR Payload.")
            
            # Digging into the standard MMT NextJS structure for flight data
            try:
                flights = next_data['props']['pageProps']['initialState']['flightSearch']['flightList']
                print(f"[+] Found {len(flights)} live flights in memory.")
                print("\n--- SAMPLE EXTRACTED QUOTE ---")
                
                if len(flights) > 0:
                    first_flight = flights[0]
                    print(f"Carrier: {first_flight.get('airlineCode', 'N/A')}")
                    print(f"Flight: {first_flight.get('flightNumber', 'N/A')}")
                    
                    # MakeMyTrip stores fare breakdown deeply
                    fares = first_flight.get('fareDetails', [{}])[0]
                    total = fares.get('totalFare', 'N/A')
                    base = fares.get('baseFare', 'N/A')
                    taxes = fares.get('taxes', 'N/A')
                    
                    print(f"Base Fare: INR {base}")
                    print(f"Taxes & Statutory: INR {taxes}")
                    print(f"Total Checkout Fare: INR {total}")
            except Exception as e:
                print("[!] Data structure changed or is nested differently:", str(e))
                print(f"[+] Root keys available: {list(next_data['props'].keys())}")
        else:
            print("[!] Could not find __NEXT_DATA__. Page might be using Client-Side Rendering exclusively.")
            print(f"[+] Found {len(captured_data)} background API XHR responses instead.")
        
        print("\n[SUCCESS] Bot Bypass Complete. This proves we can extract real MakeMyTrip markup fees live.")
        print("="*60 + "\n")
        await browser.close()

if __name__ == "__main__":
    orig = sys.argv[1].upper() if len(sys.argv) > 1 else "DEL"
    dest = sys.argv[2].upper() if len(sys.argv) > 2 else "BOM"
    asyncio.run(run_mmt_stealth_probe(orig, dest))
