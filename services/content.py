import asyncio
import json
import os
import re
from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup
from markdownify import markdownify

from models import ALLOWED_LLM_MODELS

from .log_filter import logger


async def process_content(
    html: str,
    output_format: str,
    base_url: str,
    strip_links: bool = False,
    llm_api_key: str | None = None,
    llm_provider: str = "openai",
    json_schema: dict | None = None,
    css_selector: str | None = None,
    llm_model: str | None = None,
    extraction_prompt: str | None = None,
) -> str | dict:
    # DOM Slicing (Pruning) if css_selector is provided
    if css_selector:
        logger.info(f"Applying DOM pruning with selector: {css_selector}")
        soup = BeautifulSoup(html, "lxml")
        selected_elements = soup.select(css_selector)
        if selected_elements:
            html = "".join(str(elem) for elem in selected_elements)
        else:
            logger.warning(f"CSS Selector '{css_selector}' not found in DOM.")
            html = "<!-- CSS Selector not found -->"

    if output_format == "html":
        return html

    if output_format == "markdown":
        soup = BeautifulSoup(html, "lxml")

        # Remove structural tag elements
        for tag in soup(
            [
                "script",
                "style",
                "noscript",
                "iframe",
                "svg",
                "canvas",
                "nav",
                "footer",
                "header",
                "aside",
                "form",
            ]
        ):
            tag.decompose()

        # Remove navigation/banner layout roles
        for tag in soup.find_all(
            attrs={"role": ["navigation", "banner", "complementary"]}
        ):
            tag.decompose()

        # Clean specific layout/interaction attributes from remaining DOM tags
        for tag in soup.find_all(True):
            attrs_to_remove = []
            for attr in list(tag.attrs.keys()):
                if attr in ("class", "id", "style", "onclick") or attr.startswith(
                    "data-"
                ):
                    attrs_to_remove.append(attr)
            for attr in attrs_to_remove:
                del tag[attr]

        markdown_text = markdownify(
            str(soup), heading_style="ATX", strip=["a"] if strip_links else []
        )
        return markdown_text

    if output_format == "structured":
        resolved_key = llm_api_key or os.getenv(f"{llm_provider.upper()}_API_KEY")

        if resolved_key is None:
            soup = BeautifulSoup(html, "lxml")

            title_tag = soup.find("title")
            title = title_tag.get_text().strip() if title_tag else ""

            meta_desc_tag = soup.find("meta", attrs={"name": "description"})
            meta_desc = (
                meta_desc_tag.get("content", "").strip() if meta_desc_tag else ""
            )

            meta_kw_tag = soup.find("meta", attrs={"name": "keywords"})
            meta_kw = meta_kw_tag.get("content", "").strip() if meta_kw_tag else ""

            h1_list = [
                h.get_text().strip()
                for h in soup.find_all("h1")
                if h.get_text().strip()
            ]
            h2_list = [
                h.get_text().strip()
                for h in soup.find_all("h2")
                if h.get_text().strip()
            ]
            h3_list = [
                h.get_text().strip()
                for h in soup.find_all("h3")
                if h.get_text().strip()
            ]

            links = []
            seen_hrefs = set()
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                resolved_href = urljoin(base_url, href)
                if resolved_href not in seen_hrefs:
                    seen_hrefs.add(resolved_href)
                    links.append({"text": a.get_text().strip(), "href": resolved_href})

            images = []
            for img in soup.find_all("img", src=True):
                src = img["src"].strip()
                resolved_src = urljoin(base_url, src)
                images.append({"alt": img.get("alt", "").strip(), "src": resolved_src})

            tables = []
            for table in soup.find_all("table"):
                headers = []
                rows = []
                for th in table.find_all("th"):
                    headers.append(th.get_text().strip())
                for tr in table.find_all("tr"):
                    row_cells = []
                    tds = tr.find_all("td")
                    if tds:
                        for td in tds:
                            row_cells.append(td.get_text().strip())
                        rows.append(row_cells)
                tables.append({"headers": headers, "rows": rows})

            forms = []
            for form in soup.find_all("form"):
                inputs = []
                for inp in form.find_all("input"):
                    inputs.append(
                        {
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "placeholder": inp.get("placeholder", ""),
                        }
                    )
                forms.append(
                    {
                        "action": urljoin(base_url, form.get("action", "")),
                        "method": form.get("method", "get").lower(),
                        "inputs": inputs,
                    }
                )

            text_blocks = []
            for p in soup.find_all("p"):
                txt = p.get_text().strip()
                if txt:
                    text_blocks.append(txt)
                    if len(text_blocks) >= 50:
                        break

            return {
                "title": title,
                "meta_description": meta_desc,
                "meta_keywords": meta_kw,
                "h1": h1_list,
                "h2": h2_list,
                "h3": h3_list,
                "links": links,
                "images": images,
                "tables": tables,
                "forms": forms,
                "text_blocks": text_blocks,
            }
        elif output_format == "structured":
            # LLM Structured Mapping Path
            markdown_content = await process_content(
                html=html,
                output_format="markdown",
                base_url=base_url,
                strip_links=strip_links,
                css_selector=None,  # Already cropped if css_selector was present
            )
            truncated_markdown = markdown_content[:12000]

            system = "You are a data extractor. Extract data from the markdown and return ONLY a valid JSON object matching the schema. No explanation, no markdown fences, no preamble."
            if extraction_prompt:
                system += f" Extraction Instructions: {extraction_prompt}"

            schema_str = (
                json.dumps(json_schema)
                if json_schema
                else "Return a structured JSON object reflecting the extracted data."
            )
            user = f"Schema:\n{schema_str}\n\nContent:\n{truncated_markdown}"

            providers_to_try = [llm_provider]
            for p in ["openai", "gemini", "anthropic"]:
                if p != llm_provider:
                    providers_to_try.append(p)

            result = ""
            provider_success = False
            last_err_msg = ""
            payload: dict[str, Any] = {}

            for current_provider in providers_to_try:
                if provider_success:
                    break

                current_key = (
                    llm_api_key
                    if current_provider == llm_provider
                    else os.getenv(f"{current_provider.upper()}_API_KEY")
                )
                if not current_key:
                    continue

                for attempt in range(2):
                    try:
                        async with httpx.AsyncClient(timeout=60.0) as client:
                            if current_provider == "openai":
                                target_model = (
                                    llm_model
                                    if (
                                        current_provider == llm_provider
                                        and llm_model
                                        and llm_model in ALLOWED_LLM_MODELS
                                    )
                                    else "gpt-4o-mini"
                                )
                                if llm_model and llm_model not in ALLOWED_LLM_MODELS:
                                    logger.warning(
                                        "Requested LLM model %s not in ALLOWED_LLM_MODELS. Falling back to %s",
                                        llm_model,
                                        target_model,
                                    )
                                req_headers = {
                                    "Authorization": f"Bearer {current_key}",
                                    "Content-Type": "application/json",
                                }
                                payload = {
                                    "model": target_model,
                                    "messages": [
                                        {"role": "system", "content": system},
                                        {"role": "user", "content": user},
                                    ],
                                    "max_tokens": 2000,
                                }
                                if json_schema:
                                    payload["response_format"] = {
                                        "type": "json_schema",
                                        "json_schema": {
                                            "name": "extracted_data",
                                            "strict": True,
                                            "schema": json_schema,
                                        },
                                    }
                                else:
                                    payload["response_format"] = {"type": "json_object"}

                                logger.info(
                                    f"Requesting OpenAI structured outputs using model: {target_model} (attempt {attempt + 1})"
                                )
                                resp = await client.post(
                                    "https://api.openai.com/v1/chat/completions",
                                    headers=req_headers,
                                    json=payload,
                                )
                                resp.raise_for_status()
                                result = resp.json()["choices"][0]["message"]["content"]
                            elif current_provider == "anthropic":
                                target_model = (
                                    llm_model
                                    if (
                                        current_provider == llm_provider
                                        and llm_model
                                        and llm_model in ALLOWED_LLM_MODELS
                                    )
                                    else "claude-3-5-sonnet-20241022"
                                )
                                if llm_model and llm_model not in ALLOWED_LLM_MODELS:
                                    logger.warning(
                                        "Requested LLM model %s not in ALLOWED_LLM_MODELS. Falling back to %s",
                                        llm_model,
                                        target_model,
                                    )
                                req_headers = {
                                    "x-api-key": current_key,
                                    "anthropic-version": "2023-06-01",
                                    "Content-Type": "application/json",
                                }
                                payload = {
                                    "model": target_model,
                                    "max_tokens": 2000,
                                    "system": system,
                                    "messages": [{"role": "user", "content": user}],
                                }
                                logger.info(
                                    f"Requesting Anthropic structured outputs using model: {target_model} (attempt {attempt + 1})"
                                )
                                resp = await client.post(
                                    "https://api.anthropic.com/v1/messages",
                                    headers=req_headers,
                                    json=payload,
                                )
                                resp.raise_for_status()
                                result = resp.json()["content"][0]["text"]
                            elif current_provider == "gemini":
                                target_model = (
                                    llm_model
                                    if (
                                        current_provider == llm_provider
                                        and llm_model
                                        and llm_model in ALLOWED_LLM_MODELS
                                    )
                                    else os.getenv("GEMINI_MODEL", "gemini-3.7-flash")
                                )
                                if llm_model and llm_model not in ALLOWED_LLM_MODELS:
                                    logger.warning(
                                        "Requested LLM model %s not in ALLOWED_LLM_MODELS. Falling back to %s",
                                        llm_model,
                                        target_model,
                                    )
                                url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={current_key}"
                                req_headers = {"Content-Type": "application/json"}
                                payload = {
                                    "contents": [
                                        {"parts": [{"text": system + "\n\n" + user}]}
                                    ],
                                    "generationConfig": {
                                        "responseMimeType": "application/json"
                                    },
                                }
                                if json_schema:
                                    payload["generationConfig"]["responseSchema"] = (
                                        json_schema
                                    )

                                logger.info(
                                    f"Requesting Gemini structured outputs using model: {target_model} (attempt {attempt + 1})"
                                )
                                resp = await client.post(
                                    url, headers=req_headers, json=payload
                                )
                                resp.raise_for_status()
                                result = resp.json()["candidates"][0]["content"][
                                    "parts"
                                ][0]["text"]
                        provider_success = True
                        break
                    except Exception as llm_err:
                        last_err_msg = str(llm_err)
                        if attempt < 1:
                            wait = 2.0 * (attempt + 1)
                            logger.warning(
                                f"LLM API request ({current_provider}) failed: {llm_err}. Retrying in {wait}s..."
                            )
                            await asyncio.sleep(wait)
                        else:
                            logger.error(
                                f"LLM API request ({current_provider}) failed after 2 attempts."
                            )

            if not provider_success:
                return {
                    "error": "llm_api_failed",
                    "error_message": f"All available LLM providers failed. Last error: {last_err_msg}",
                }

            result = result.strip()
            if result.startswith("```"):
                result = re.sub(r"^```(?:json)?\n", "", result)
                result = re.sub(r"\n```$", "", result)
                result = result.strip()

            try:
                return json.loads(result)
            except Exception as e:
                logger.error(f"Failed to parse LLM response as JSON: {e}")
                return {"error": "llm_parse_failed", "raw": result}

    # Fallback for unknown formats
    return html
