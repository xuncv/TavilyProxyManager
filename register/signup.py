"""
Tavily Auto Sign Up
Automatically sign up for Tavily using vision model for captcha recognition
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
import base64
import re
import sys
import io
import os
import yaml
import json
from datetime import datetime
import time
from email import message_from_string

# SVG to PNG conversion (svglib)
try:
    from svglib.svglib import svg2rlg
    HAS_SVGLIB = True
except Exception:
    HAS_SVGLIB = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

# Fix Windows console encoding + ensure logs are flushed promptly.
# batch_signup.py imports this module; if stdout gets wrapped without line buffering,
# prints may appear delayed. Prefer reconfigure when available.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True, write_through=True)
    except Exception:
        try:
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer,
                encoding="utf-8",
                errors="replace",
                line_buffering=True,
                write_through=True,
            )
        except Exception:
            pass

    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True, write_through=True)
    except Exception:
        try:
            sys.stderr = io.TextIOWrapper(
                sys.stderr.buffer,
                encoding="utf-8",
                errors="replace",
                line_buffering=True,
                write_through=True,
            )
        except Exception:
            pass


def load_config(config_path: str = None) -> dict:
    """
    加载配置文件

    Args:
        config_path: 配置文件路径

    Returns:
        配置字典
    """
    if config_path is None:
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")

    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    return config


def create_session() -> requests.Session:
    """
    创建配置好的请求会话

    Returns:
        requests.Session 对象
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    return session


def svg_to_png_base64(svg_base64: str) -> str | None:
    """
    将SVG的base64转换为PNG的base64

    Args:
        svg_base64: SVG的base64编码

    Returns:
        PNG的base64编码
    """
    # 解码SVG
    svg_data = base64.b64decode(svg_base64)

    if not HAS_SVGLIB:
        return None

    # 使用 svglib + reportlab(renderPM) 转换
    import tempfile

    svg_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as f:
            svg_path = f.name
            f.write(svg_data)

        drawing = svg2rlg(svg_path)
        if not drawing:
            return None

        try:
            from reportlab import rl_config

            try:
                import _rl_renderPM  # noqa: F401

                rl_config.renderPMBackend = "_renderPM"
            except ImportError:
                # Fallback to Cairo backend (via rlPyCairo/pycairo) when the
                # compiled renderPM extension isn't available.
                rl_config.renderPMBackend = "rlPyCairo"

            from reportlab.graphics import renderPM
        except Exception:
            return None

        png_data = renderPM.drawToString(drawing, fmt="PNG")
        return base64.b64encode(png_data).decode("utf-8")
    except Exception:
        return None
    finally:
        if svg_path and os.path.exists(svg_path):
            try:
                os.unlink(svg_path)
            except Exception:
                pass

    # 如果没有可用的转换库，返回None
    return None


def get_signup_page(session: requests.Session, return_to: str = "/home") -> dict:
    """
    获取注册页面URL和相关信息

    Args:
        session: requests会话对象
        return_to: 注册成功后的跳转路径

    Returns:
        包含注册页面信息的字典
    """
    result = {
        "success": False,
        "signup_url": None,
        "state": None,
        "html": None,
    }

    # Step 1: 调用登录 API 入口
    login_api_url = f"https://app.tavily.com/api/auth/login?returnTo={return_to}"
    print(f"[1] 请求登录 API: {login_api_url}")

    response = session.get(login_api_url, allow_redirects=False)
    if response.status_code != 302:
        print(f"    错误: 期望 302，得到 {response.status_code}")
        return result

    # Step 2: 获取 Auth0 authorize URL
    auth0_url = response.headers.get("Location")
    print(f"[2] Auth0 授权 URL 获取成功")

    response = session.get(auth0_url, allow_redirects=False)
    if response.status_code != 302:
        print(f"    错误: 期望 302，得到 {response.status_code}")
        return result

    # Step 3: 获取登录页面 URL，然后转换为注册页面URL
    login_page_url = response.headers.get("Location")
    if login_page_url.startswith("/"):
        login_page_url = urljoin("https://auth.tavily.com", login_page_url)

    # 将 login 转换为 signup
    signup_page_url = login_page_url.replace("/u/login/identifier", "/u/signup/identifier")
    print(f"[3] 注册页面 URL: {signup_page_url[:60]}...")

    # 提取 state 参数
    parsed = urlparse(signup_page_url)
    params = parse_qs(parsed.query)
    state = params.get("state", [None])[0]

    result["signup_url"] = signup_page_url
    result["state"] = state
    result["success"] = True

    return result


def fetch_page_with_captcha(session: requests.Session, url: str) -> dict:
    """
    获取页面并提取验证码

    Args:
        session: requests会话对象
        url: 页面URL

    Returns:
        包含页面HTML和验证码信息的字典
    """
    result = {
        "success": False,
        "html": None,
        "captcha_base64": None,
        "captcha_data_url": None,
    }

    print(f"[4] 请求注册页面...")
    response = session.get(url)

    if response.status_code != 200:
        print(f"    错误: 请求页面失败，状态码 {response.status_code}")
        return result

    html_content = response.text
    print(f"    页面大小: {len(html_content)} 字节")

    # 提取验证码
    print(f"[5] 提取验证码...")
    pattern = r'data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)'
    matches = re.findall(pattern, html_content)

    if matches:
        captcha_base64 = max(matches, key=len)
        result["captcha_base64"] = captcha_base64
        result["captcha_data_url"] = f"data:image/svg+xml;base64,{captcha_base64}"
        print(f"    找到验证码 (base64长度: {len(captcha_base64)})")
    else:
        print("    警告: 未找到验证码图片")

    result["html"] = html_content
    result["success"] = True

    return result


def recognize_captcha_with_vision(captcha_base64: str, config: dict) -> str:
    """
    使用视觉大模型识别验证码

    Args:
        captcha_base64: base64编码的验证码图片(SVG格式)
        config: 配置字典

    Returns:
        识别出的验证码文本
    """
    print(f"[6] 使用视觉模型识别验证码...")

    # 先将SVG转换为PNG（比直接上传SVG更通用/稳定）
    print("    转换SVG为PNG...")
    png_base64 = svg_to_png_base64(captcha_base64)
    if not png_base64:
        print("    错误: SVG转PNG失败，请安装 svglib+reportlab")
        return None

    print(f"    PNG大小: {len(png_base64)} bytes")

    api_url = f"{config['OPENAI_BASEURL']}/chat/completions"
    api_key = config['OPENAI_API_KEY']
    model = config['OPENAI_MODEL']

    # 构建请求
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Please identify the text/characters shown in this captcha image. Output only the captcha text, nothing else. The captcha typically consists of 6 alphanumeric characters and is case-sensitive.",
                    },
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{png_base64}"}},
                ],
            }
        ],
        "max_tokens": 50,
        "temperature": 0,
    }

    print(f"    API: {api_url}")
    print(f"    Model: {model}")

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()

        result = response.json()
        captcha_text = result["choices"][0]["message"]["content"].strip()

        # 清理结果，只保留字母和数字
        captcha_text = re.sub(r'[^A-Za-z0-9]', '', captcha_text)

        print(f"    识别结果: {captcha_text}")
        return captcha_text

    except requests.exceptions.RequestException as e:
        print(f"    错误: API请求失败 - {e}")
        return None
    except (KeyError, IndexError) as e:
        print(f"    错误: 解析响应失败 - {e}")
        return None


def fetch_emails_from_temp_mail(mail_api_base: str, jwt: str, limit: int = 10, offset: int = 0) -> list:
    """
    从临时邮箱服务获取邮件列表

    Args:
        mail_api_base: 邮箱API基础地址
        jwt: JWT认证令牌
        limit: 返回邮件数量限制
        offset: 偏移量

    Returns:
        邮件列表
    """
    url = f"{mail_api_base}/api/mails?limit={limit}&offset={offset}"
    headers = {
        "Authorization": f"Bearer {jwt}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get("results", [])
    except requests.exceptions.RequestException as e:
        print(f"    获取邮件失败: {e}")
        return []


def decode_email_body(raw: str) -> str:
    """
    解码邮件正文内容

    Args:
        raw: 邮件原始内容

    Returns:
        解码后的正文
    """
    try:
        msg = message_from_string(raw)
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ["text/plain", "text/html"]:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            body += payload.decode(charset, errors='replace')
                        except:
                            body += payload.decode('utf-8', errors='replace')
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                try:
                    body = payload.decode(charset, errors='replace')
                except:
                    body = payload.decode('utf-8', errors='replace')

        return body
    except Exception as e:
        # 如果解析失败，返回原始内容
        return raw


def extract_verification_link(email_raw: str) -> str:
    """
    从邮件原始内容中提取验证链接

    Args:
        email_raw: 邮件原始内容

    Returns:
        验证链接，未找到返回None
    """
    # 先解码邮件内容
    body = decode_email_body(email_raw)

    # 匹配 Tavily/Auth0 验证链接的模式
    patterns = [
        r'https://auth\.tavily\.com/u/email-verification\?ticket=[A-Za-z0-9_\-]+',
        r'https://auth\.tavily\.com/u/email-verification\?ticket=[^\s\"\'\<\>]+',
        r'https://[^\s\"\'\<\>]*tavily[^\s\"\'\<\>]*verify[^\s\"\'\<\>]+',
        r'https://[^\s\"\'\<\>]*tavily[^\s\"\'\<\>]*confirmation[^\s\"\'\<\>]+',
        r'href=["\']?(https://[^\s\"\'\<\>]*ticket=[^\s\"\'\<\>]+)',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            link = matches[0]
            # 清理链接中可能的HTML编码
            link = link.replace('&amp;', '&')
            # 移除末尾可能的引号、尖括号或#号
            link = re.sub(r'["\'\<\>#]+$', '', link)
            return link

    return None


def wait_for_verification_email(mail_api_base: str, jwt: str, timeout: int = 120, poll_interval: int = 5) -> str:
    """
    等待验证邮件并提取验证链接

    Args:
        mail_api_base: 邮箱API基础地址
        jwt: JWT认证令牌
        timeout: 超时时间（秒）
        poll_interval: 轮询间隔（秒）

    Returns:
        验证链接，超时返回None
    """
    print(f"\n[9] 等待验证邮件...")
    start_time = time.time()

    while time.time() - start_time < timeout:
        emails = fetch_emails_from_temp_mail(mail_api_base, jwt)

        for email in emails:
            raw = email.get("raw", "")
            source = email.get("source", "")

            # 检查是否是 Tavily/Auth0 发送的邮件
            if "tavily" in source.lower() or "auth0" in source.lower():
                print(f"    找到来自 {source} 的邮件")
                link = extract_verification_link(raw)
                if link:
                    print(f"    提取到验证链接: {link[:60]}...")
                    return link

        elapsed = int(time.time() - start_time)
        print(f"    等待中... ({elapsed}s/{timeout}s)")
        time.sleep(poll_interval)

    print(f"    超时: 未收到验证邮件")
    return None


def verify_email(session: requests.Session, verification_link: str) -> dict:
    """
    使用注册时的session访问验证链接完成邮箱验证

    Args:
        session: 注册时使用的requests会话对象
        verification_link: 验证链接

    Returns:
        验证结果
    """
    result = {
        "success": False,
        "error": None,
        "final_url": None,
    }

    print(f"\n[10] 访问验证链接...")

    try:
        # 使用注册时的 session 访问验证链接（通常会先 GET 一次拿到 state，再 POST 提交表单，302 跳转）
        response = session.get(verification_link, allow_redirects=True, timeout=30)
        print(f"    状态码: {response.status_code}")
        print(f"    URL: {response.url[:60]}...")

        result["final_url"] = response.url

        def _origin_from_url(u: str) -> str:
            try:
                p = urlparse(u)
                if p.scheme and p.netloc:
                    return f"{p.scheme}://{p.netloc}"
            except Exception:
                pass
            return "https://auth.tavily.com"

        def _extract_first_form_html(page_html: str) -> str | None:
            if not page_html:
                return None
            # Prefer a POST form if present; otherwise fall back to the first form.
            m = re.search(r'(<form[^>]*method="post"[^>]*>.*?</form>)', page_html, flags=re.IGNORECASE | re.DOTALL)
            if m:
                return m.group(1)
            m = re.search(r"(<form[^>]*>.*?</form>)", page_html, flags=re.IGNORECASE | re.DOTALL)
            return m.group(1) if m else None

        # 有些验证页需要提交 1~N 次确认表单（GET -> POST(state) -> 302 -> ...）
        max_forms = 5
        for _ in range(max_forms):
            if response.status_code != 200:
                break

            # 如果已经到达登录/注册页面，视为验证流程已结束（可能已验证但未自动登录）
            if "/u/login" in (response.url or "") or "/u/signup" in (response.url or ""):
                print(f"    已到达登录/注册页面，验证流程结束")
                result["success"] = True
                result["final_url"] = response.url
                return result

            html = response.text or ""
            state_match = re.search(r'name="state"\s+value="([^"]+)"', html)
            form_html = _extract_first_form_html(html)

            # 无 state 或无表单：无法继续提交
            if not state_match or not form_html:
                break

            state = state_match.group(1)

            action_match = re.search(r'<form[^>]*action="([^"]*)"', form_html, flags=re.IGNORECASE)
            form_url = response.url
            if action_match:
                action = (action_match.group(1) or "").strip()
                if action:
                    form_url = urljoin(response.url, action)

            form_data = extract_form_data(form_html) or {}
            form_data["state"] = state

            action_value = _extract_action_value(form_html)
            if action_value:
                form_data["action"] = action_value

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": _origin_from_url(form_url),
                "Referer": response.url,
            }

            print(f"    发现确认表单，提交 state... (期望 302)")
            post_resp = session.post(form_url, data=form_data, headers=headers, allow_redirects=False, timeout=30)
            print(f"    表单提交状态: {post_resp.status_code}")

            # 手动跟随 302，便于观察跳转链路（requests 自动跟随也会工作，但这里更可控）
            if post_resp.status_code in (301, 302, 303, 307, 308) and post_resp.headers.get("Location"):
                next_url = urljoin(form_url, post_resp.headers["Location"])
                response = session.get(next_url, allow_redirects=True, timeout=30)
                print(f"    跳转后状态: {response.status_code}")
                print(f"    跳转后URL: {response.url[:60]}...")
                result["final_url"] = response.url
                continue

            # 如果不是跳转（可能仍停留在确认页），继续循环尝试下一次表单
            response = post_resp
            result["final_url"] = getattr(response, "url", result["final_url"])

        # 检查最终结果
        if "app.tavily.com" in response.url:
            result["success"] = True
            result["final_url"] = response.url
            print(f"    已跳转到应用页面，验证成功!")
        elif response.status_code == 200:
            if "verified" in html.lower() or "success" in html.lower():
                result["success"] = True
                print(f"    邮箱验证成功!")
            else:
                # 保存页面用于调试
                debug_path = os.path.join(os.path.dirname(__file__), "debug_verify_final.html")
                with open(debug_path, "w", encoding="utf-8") as f:
                    f.write(html)
                print(f"    验证页面已保存到 {debug_path}")
                result["success"] = True
                print(f"    验证请求已完成")

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        print(f"    验证请求错误: {e}")

    return result


def login_after_verification(session: requests.Session, email: str, password: str, config: dict) -> dict:
    """
    邮箱验证后登录获取API Keys

    Args:
        session: requests会话对象
        email: 邮箱
        password: 密码
        config: 配置字典

    Returns:
        登录结果
    """
    result = {
        "success": False,
        "error": None,
        "error_code": None,
        "status_code": None,
    }

    print(f"\n[11] 登录账户...")

    try:
        # Step 1: 获取登录页面
        login_api_url = "https://app.tavily.com/api/auth/login?returnTo=/home"
        response = session.get(login_api_url, allow_redirects=False, timeout=30)

        if response.status_code != 302:
            result["error"] = f"获取登录页面失败: {response.status_code}"
            result["status_code"] = response.status_code
            print(f"    {result['error']}")
            return result

        auth0_url = response.headers.get("Location")
        response = session.get(auth0_url, allow_redirects=False, timeout=30)

        if response.status_code != 302:
            result["error"] = f"Auth0重定向失败: {response.status_code}"
            result["status_code"] = response.status_code
            print(f"    {result['error']}")
            return result

        login_page_url = response.headers.get("Location")
        if login_page_url.startswith("/"):
            login_page_url = f"https://auth.tavily.com{login_page_url}"

        # Step 2: 获取登录页面和验证码
        response = session.get(login_page_url, timeout=30)
        if response.status_code != 200:
            result["error"] = f"获取登录页面失败: {response.status_code}"
            result["status_code"] = response.status_code
            print(f"    {result['error']}")
            return result

        html = response.text
        print(f"    登录页面大小: {len(html)} 字节")

        # 检查是否已经登录成功
        if "app.tavily.com" in response.url:
            result["success"] = True
            print(f"    已登录，跳转到应用!")
            return result

        form_html = _extract_primary_form_html(html)

        # 提取state
        extracted = extract_form_data(form_html)
        state = extracted.get("state") or None
        action_value = _extract_action_value(form_html)

        # 提取验证码
        pattern = r'data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)'
        matches = re.findall(pattern, html)

        # 检查页面类型
        is_password_page = "/u/login/password" in response.url or "password" in html.lower()[:2000]

        if not matches:
            # 保存HTML用于调试
            debug_path = os.path.join(os.path.dirname(__file__), "debug_login.html")
            with open(debug_path, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"    登录页面已保存到 {debug_path}")
            print(f"    当前URL: {response.url}")

            # 如果是密码页面（无验证码），直接尝试提交密码
            if is_password_page:
                print(f"    检测到密码页面，尝试直接登录...")
                # 跳过验证码步骤，直接提交密码
                extracted_pw = extract_form_data(form_html)
                form_data = dict(extracted_pw)
                form_data["state"] = extracted_pw.get("state") or state
                form_data["username"] = email
                form_data["password"] = password
                form_data["action"] = _extract_action_value(form_html)

                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://auth.tavily.com",
                    "Referer": response.url,
                }

                response = session.post(response.url, data=form_data, headers=headers, allow_redirects=True, timeout=30)
                print(f"    登录状态: {response.status_code}")
                print(f"    最终URL: {response.url[:60]}...")

                if "app.tavily.com" in response.url:
                    result["success"] = True
                    print(f"    登录成功!")
                else:
                    result["error"] = "登录失败，未能跳转到应用"
                    result["status_code"] = response.status_code
                    print(f"    {result['error']}")
                return result
            else:
                result["error"] = "未找到登录验证码"
                print(f"    {result['error']}")
                return result

        captcha_base64 = max(matches, key=len)
        print(f"    找到验证码")

        # Step 3: 识别验证码
        captcha_text = recognize_captcha_with_vision(captcha_base64, config)
        if not captcha_text:
            result["error"] = "验证码识别失败"
            print(f"    {result['error']}")
            return result

        print(f"    验证码: {captcha_text}")

        # Step 4: 提交登录表单 (第一步: 邮箱)
        extracted_login = extract_form_data(form_html)
        form_data = dict(extracted_login)
        form_data["state"] = extracted_login.get("state") or state
        form_data["username"] = email
        form_data["captcha"] = captcha_text
        form_data["action"] = action_value

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://auth.tavily.com",
            "Referer": login_page_url,
        }

        response = session.post(login_page_url, data=form_data, headers=headers, allow_redirects=False, timeout=30)
        print(f"    邮箱提交状态: {response.status_code}")

        if response.status_code != 302:
            error_code = _extract_error_code(response.text)
            result["error"] = f"邮箱提交失败: {response.status_code}" + (f" ({error_code})" if error_code else "")
            result["status_code"] = response.status_code
            result["error_code"] = error_code
            print(f"    {result['error']}")
            return result

        # Step 5: 获取密码页面
        password_url = response.headers.get("Location")
        if password_url.startswith("/"):
            password_url = f"https://auth.tavily.com{password_url}"

        response = session.get(password_url, timeout=30)
        if response.status_code != 200:
            result["error"] = f"获取密码页面失败: {response.status_code}"
            result["status_code"] = response.status_code
            print(f"    {result['error']}")
            return result

        pw_html = response.text
        pw_form_html = _extract_primary_form_html(pw_html)
        extracted_pw = extract_form_data(pw_form_html)
        state = extracted_pw.get("state") or state
        pw_action_value = _extract_action_value(pw_form_html)

        # Step 6: 提交密码
        form_data = dict(extracted_pw)
        form_data["state"] = state
        form_data["username"] = email
        form_data["password"] = password
        form_data["action"] = pw_action_value

        response = session.post(password_url, data=form_data, headers=headers, allow_redirects=True, timeout=30)
        print(f"    登录状态: {response.status_code}")
        print(f"    最终URL: {response.url[:60]}...")

        if "app.tavily.com" in response.url:
            result["success"] = True
            print(f"    登录成功!")
        else:
            result["error"] = "登录失败，未能跳转到应用"
            result["status_code"] = response.status_code
            print(f"    {result['error']}")

    except requests.exceptions.RequestException as e:
        result["error"] = f"请求异常: {e}"
        print(f"    {result['error']}")
    except Exception as e:
        result["error"] = f"未知错误: {e}"
        print(f"    {result['error']}")

    return result


def create_api_key(
    session: requests.Session,
    key_name: str = "default",
    *,
    limit: int = 2147483647,
    key_type: str = "development",
    search_egress_policy: str = "allow_external",
    oid: str | None = None,
) -> dict:
    """
    创建新的API Key

    Args:
        session: 已登录的requests会话对象
        key_name: Key名称

    Returns:
        创建结果
    """
    result = {
        "success": False,
        "key": None,
        "error": None,
    }

    print(f"\n[12] 创建API Key...")

    try:
        # NOTE:
        # Tavily 前端创建 key 的请求是：POST /api/keys?oid=<oid or empty>
        # 且 body 至少包含 name + limit，否则会 400 Bad Request。
        # 参考：home 页面 bundle 内的调用（minified）
        #   fetch("/api/keys?oid="+..., { name, limit, key_type, search_egress_policy })
        if oid is None:
            oid = ""

        url = f"https://app.tavily.com/api/keys?oid={oid}"
        payload = {
            "name": key_name,
            "limit": int(limit),
            "key_type": key_type,
            "search_egress_policy": search_egress_policy,
        }

        headers = {
            "Origin": "https://app.tavily.com",
            "Referer": "https://app.tavily.com/home",
            "Accept": "application/json",
        }

        response = session.post(url, json=payload, headers=headers, timeout=30)

        print(f"    状态码: {response.status_code}")

        if response.status_code in [200, 201]:
            try:
                data = response.json()
            except ValueError:
                data = {"raw": response.text}
                result["error"] = "响应不是有效的 JSON"
                print(f"    警告: 响应不是有效的 JSON: {response.text[:200]}")
                return result

            # 验证响应中是否包含有效的 key
            key_value = data.get("key", data.get("api_key", data.get("apiKey", ""))) if isinstance(data, dict) else ""
            if key_value and isinstance(key_value, str) and key_value.startswith("tvly-"):
                result["success"] = True
                result["key"] = data
                print(f"    创建成功: {key_value[:8]}...{key_value[-4:]}")
            else:
                # 状态码是 200/201 但没有有效的 key
                result["error"] = f"响应中没有有效的 key: {data}"
                print(f"    警告: 状态码 {response.status_code} 但没有有效的 key")
                print(f"    响应: {data}")
        elif response.status_code == 401:
            result["error"] = "未授权 (session 无效或已过期)"
            print(f"    错误: 401 Unauthorized - session 无效")
        elif response.status_code == 403:
            result["error"] = "禁止访问 (可能需要验证邮箱或账户受限)"
            print(f"    错误: 403 Forbidden")
        else:
            result["error"] = f"创建失败，状态码: {response.status_code}"
            print(f"    {result['error']}")
            # 打印响应内容帮助调试
            try:
                print(f"    响应: {response.text[:200]}")
            except:
                pass

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        print(f"    请求错误: {e}")

    return result


def run_first_login_init(session: requests.Session, *, debug: bool = False) -> dict:
    """
    模拟新账号首次进入应用后的初始化流程。

    现象：通过激活邮件链接拿到 session 后，如果不走前端的新手引导/弹窗，
    后端可能不会生成默认 API Key。浏览器通常会触发：
      1) GET  /api/account        (new_user: true)
      2) GET  /api/hasSeenTour    ({hasSeenTour:false})
      3) PUT  /api/hasSeenTour
      4) POST /api/marketing-optin

    本函数会尽量按上述顺序调用（容错：状态码/字段不一致时继续）。
    """
    result = {
        "success": False,
        "account": None,
        "is_new_user": None,
        "has_seen_tour": None,
        "has_seen_marketing_popup": None,
        "marketing_opt_in": None,
        "errors": [],
    }

    headers = {
        "Accept": "application/json",
        "Origin": "https://app.tavily.com",
        "Referer": "https://app.tavily.com/home",
    }

    def _try_json(resp: requests.Response):
        try:
            return resp.json()
        except Exception:
            return resp.text

    def _is_new_user(payload) -> bool | None:
        if not isinstance(payload, dict):
            return None
        # 常见字段名做兼容；如后端结构变化，也不阻断流程。
        for k in ("new_user", "newUser", "is_new_user", "isNewUser"):
            v = payload.get(k)
            if isinstance(v, bool):
                return v
        user = payload.get("user")
        if isinstance(user, dict):
            for k in ("new_user", "newUser", "is_new_user", "isNewUser"):
                v = user.get(k)
                if isinstance(v, bool):
                    return v
        return None

    def _extract_bool(payload, key: str) -> bool | None:
        if not isinstance(payload, dict):
            return None
        v = payload.get(key)
        return v if isinstance(v, bool) else None

    def _parse_has_seen_tour(payload) -> bool | None:
        if not isinstance(payload, dict):
            return None
        for k in ("hasSeenTour", "has_seen_tour", "seenTour", "seen_tour"):
            v = payload.get(k)
            if isinstance(v, bool):
                return v
        return None

    # 1) /api/account
    try:
        if debug:
            print("    [init] GET /api/account")
        r = session.get("https://app.tavily.com/api/account", headers=headers, timeout=30)
        if debug:
            print(f"    [init] /api/account: {r.status_code}")
        payload = _try_json(r) if r.status_code == 200 else None
        result["account"] = payload
        result["is_new_user"] = _is_new_user(payload) if payload is not None else None
        result["has_seen_marketing_popup"] = _extract_bool(payload, "has_seen_marketing_popup")
        result["marketing_opt_in"] = _extract_bool(payload, "marketing_opt_in")
    except Exception as e:
        result["errors"].append(f"/api/account error: {e}")

    # 2) /api/hasSeenTour
    try:
        if debug:
            print("    [init] GET /api/hasSeenTour")
        r = session.get("https://app.tavily.com/api/hasSeenTour", headers=headers, timeout=30)
        if debug:
            print(f"    [init] /api/hasSeenTour: {r.status_code}")
        payload = _try_json(r) if r.status_code == 200 else None
        has_seen = _parse_has_seen_tour(payload) if payload is not None else None
        result["has_seen_tour"] = has_seen

        # 3) PUT /api/hasSeenTour（仅当明确为 False 时）
        if has_seen is False:
            if debug:
                print("    [init] PUT /api/hasSeenTour")
            put_payload = {"hasSeenTour": True}
            put_headers = {**headers, "Content-Type": "application/json"}
            put_resp = session.put(
                "https://app.tavily.com/api/hasSeenTour",
                json=put_payload,
                headers=put_headers,
                timeout=30,
            )
            if debug:
                print(f"    [init] PUT /api/hasSeenTour: {put_resp.status_code}")
    except Exception as e:
        result["errors"].append(f"/api/hasSeenTour error: {e}")

    # 4) POST /api/marketing-optin（仅在需要展示 marketing 弹窗时触发）
    try:
        should_post = True
        if result["has_seen_marketing_popup"] is True:
            should_post = False
        elif result["has_seen_marketing_popup"] is None and result["is_new_user"] is False:
            # 既不是新用户、又没有明确的 marketing 弹窗状态时，避免无意义写入偏好。
            should_post = False

        if should_post and debug:
            print("    [init] POST /api/marketing-optin")

        post_headers = {**headers, "Content-Type": "application/json"}
        if should_post:
            # 从 DevTools 观察到的请求体字段：{ "opt_in": boolean }
            resp = session.post(
                "https://app.tavily.com/api/marketing-optin",
                json={"opt_in": False},
                headers=post_headers,
                timeout=30,
            )
            if debug:
                print(f"    [init] /api/marketing-optin: {resp.status_code}")
    except Exception as e:
        result["errors"].append(f"/api/marketing-optin error: {e}")

    result["success"] = True
    return result


def get_api_keys(
    session: requests.Session,
    auto_create: bool = True,
    max_retries: int = 3,
    retry_delay: int = 3,
    *,
    debug_init: bool = False,
) -> dict:
    """
    获取Tavily API Keys，如果没有则等待重试（API Key会自动生成）

    Args:
        session: 已登录的requests会话对象
        auto_create: 如果没有Key是否等待重试
        max_retries: 最大重试次数
        retry_delay: 重试间隔（秒）

    Returns:
        包含API keys的字典
    """
    result = {
        "success": False,
        "keys": None,
        "error": None,
    }

    print(f"\n[12] 获取API Keys...")

    def _extract_key_value(item: dict) -> str:
        if not isinstance(item, dict):
            return ""
        return item.get("key") or item.get("api_key") or item.get("apiKey") or ""

    def _mask_secret(value: str) -> str:
        if not isinstance(value, str):
            return value
        if len(value) <= 6:
            return "***"
        if len(value) <= 12:
            return f"{value[:2]}...{value[-2:]}"
        return f"{value[:8]}...{value[-4:]}"

    def _redact_payload(obj):
        if isinstance(obj, list):
            return [_redact_payload(x) for x in obj]
        if isinstance(obj, dict):
            redacted = {}
            for k, v in obj.items():
                if k in ("key", "api_key", "apiKey") and isinstance(v, str):
                    redacted[k] = _mask_secret(v)
                else:
                    redacted[k] = _redact_payload(v)
            return redacted
        return obj

    def _normalize_keys_payload(payload):
        """
        /api/keys 可能返回：
        - list[dict]
        - dict(key=...)
        - dict(keys=[...]) / dict(data=[...]) / dict(results=[...])
        """
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            if isinstance(payload.get("keys"), list):
                return payload["keys"]
            if isinstance(payload.get("data"), list):
                return payload["data"]
            if isinstance(payload.get("results"), list):
                return payload["results"]
            return payload
        return payload

    def _warmup_app_session() -> None:
        """
        浏览器首次进入 /home 时会触发一系列 API 调用（billing / services 等）。
        新账号的默认 key 可能是异步生成的：直接拉 /api/keys 会短暂返回 []。
        这里尽量模拟浏览器的“进入应用”行为以触发后台初始化（包含新手引导相关接口）。
        """
        print("    预热 session...")
        try:
            session.get("https://app.tavily.com/home", timeout=30)
        except Exception:
            pass

        # 新账号首次登录往往需要走新手引导/弹窗相关接口，才能触发后端初始化（默认 key 生成等）。
        try:
            run_first_login_init(session, debug=debug_init)
        except Exception:
            pass

        # Observed in browser network when opening /home.
        try:
            session.post("https://app.tavily.com/api/tavily_services", json={"action": "get-stripe-accounts"}, timeout=30)
        except Exception:
            pass

        try:
            session.post("https://app.tavily.com/api/billing/has-valid-payment", json={}, timeout=30)
        except Exception:
            pass

        try:
            session.post("https://app.tavily.com/api/billing/status", json={}, timeout=30)
        except Exception:
            pass

        try:
            session.get("https://app.tavily.com/api/billing/address", timeout=30)
        except Exception:
            pass

    def _get_api_keys_via_frontend(timeout_seconds: int = 30, poll_interval_seconds: int = 2):
        """
        通过 Playwright 加载前端页面触发初始化逻辑，然后在浏览器上下文内 fetch /api/keys。
        现象：requests 直接 GET /api/keys 有时返回 []，但打开 /home 后前端会触发 key 的异步生成。
        """
        if not HAS_PLAYWRIGHT:
            return None

        # 从 requests.Session 复制 cookie 到浏览器上下文
        cookie_list = []
        for c in session.cookies:
            domain = getattr(c, "domain", None)
            if not domain or "tavily.com" not in domain:
                continue
            cookie_list.append({
                "name": c.name,
                "value": c.value,
                "domain": domain,
                "path": c.path or "/",
                "secure": bool(getattr(c, "secure", False)),
                "httpOnly": bool(getattr(c, "_rest", {}).get("HttpOnly")),
            })

        user_agent = session.headers.get(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        )

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(user_agent=user_agent)
                if cookie_list:
                    context.add_cookies(cookie_list)

                page = context.new_page()
                page.goto("https://app.tavily.com/home", timeout=60000)

                start = time.time()
                while time.time() - start < timeout_seconds:
                    data = page.evaluate('''async () => {
                        const r = await fetch("https://app.tavily.com/api/keys", { credentials: "include" });
                        const t = await r.text();
                        return { status: r.status, text: t };
                    }''')

                    status = data.get("status")
                    text = data.get("text", "")
                    if status == 200:
                        try:
                            payload = json.loads(text) if text else []
                        except Exception:
                            payload = text

                        normalized = _normalize_keys_payload(payload)
                        if isinstance(normalized, list) and len(normalized) > 0:
                            try:
                                browser.close()
                            except Exception:
                                pass
                            return normalized
                        if isinstance(normalized, dict) and _extract_key_value(normalized):
                            try:
                                browser.close()
                            except Exception:
                                pass
                            return normalized

                    page.wait_for_timeout(int(poll_interval_seconds * 1000))

                try:
                    browser.close()
                except Exception:
                    pass
        except Exception:
            return None

        return None

    warmed_up = False
    tried_frontend = False
    created_key = False
    for attempt in range(max_retries):
        try:
            # 首次尝试前先预热 session
            if attempt == 0:
                _warmup_app_session()
            elif attempt > 0:
                # 重试时等待
                print(f"    等待 {retry_delay} 秒后重试...")
                time.sleep(retry_delay)

            response = session.get("https://app.tavily.com/api/keys", timeout=30)

            print(f"    尝试 {attempt + 1}/{max_retries} - 状态码: {response.status_code}")
            if response.status_code == 200:
                try:
                    raw_payload = response.json()
                except ValueError:
                    raw_payload = response.text
                data = _normalize_keys_payload(raw_payload)

                # 检查是否有API Key
                if isinstance(data, list) and len(data) > 0:
                    result["success"] = True
                    result["keys"] = data
                    print(f"    成功获取API Keys!")
                    for i, key in enumerate(data):
                        key_value = _extract_key_value(key) or "N/A"
                        if len(key_value) > 10:
                            masked = f"{key_value[:8]}...{key_value[-4:]}"
                        else:
                            masked = key_value
                        print(f"    Key {i+1}: {masked}")
                    return result
                elif isinstance(data, dict) and _extract_key_value(data):
                    result["success"] = True
                    result["keys"] = data
                    key_value = _extract_key_value(data)
                    if key_value and len(key_value) > 10:
                        masked = f"{key_value[:8]}...{key_value[-4:]}"
                    else:
                        masked = key_value
                    print(f"    API Key: {masked}")
                    return result
                else:
                    # 便于排查：打印 /api/keys 的返回结构（脱敏）
                    try:
                        redacted = _redact_payload(raw_payload)
                        print(f"    /api/keys 返回: {json.dumps(redacted, ensure_ascii=False)[:2000]}")
                    except Exception:
                        pass

                    # 不跑浏览器 JS 的情况下，默认 key 往往不会自动生成；直接调用创建接口更稳定
                    if auto_create and not created_key:
                        created_key = True
                        print("    没有API Key，尝试直接创建默认 Key...")
                        created = create_api_key(session, key_name="default")
                        if created.get("success") and created.get("key"):
                            result["success"] = True
                            result["keys"] = [created["key"]]
                            key_value = _extract_key_value(created["key"]) or "N/A"
                            print(f"    已创建 API Key: {_mask_secret(key_value)}")
                            return result

                    # 新账号可能需要“进入应用”触发初始化逻辑，先模拟一次浏览器行为
                    if auto_create and not warmed_up:
                        warmed_up = True
                        print("    尝试触发初始化（访问 /home + billing/services）...")
                        _warmup_app_session()
                    elif auto_create and warmed_up and not tried_frontend:
                        tried_frontend = True
                        print("    尝试通过前端页面触发 Key 生成（Playwright）...")
                        frontend_keys = _get_api_keys_via_frontend(timeout_seconds=30, poll_interval_seconds=2)
                        if frontend_keys:
                            result["success"] = True
                            result["keys"] = frontend_keys
                            print(f"    前端获取到API Keys!")
                            if isinstance(frontend_keys, list):
                                for i, key in enumerate(frontend_keys):
                                    key_value = _extract_key_value(key) or "N/A"
                                    print(f"    Key {i+1}: {_mask_secret(key_value)}")
                            elif isinstance(frontend_keys, dict):
                                print(f"    API Key: {_mask_secret(_extract_key_value(frontend_keys))}")
                            return result
                    # 没有Key，等待重试
                    if attempt < max_retries - 1:
                        print(f"    没有API Key，等待 {retry_delay} 秒后重试...")
                        time.sleep(retry_delay)
                    else:
                        print(f"    没有API Key")
                        result["success"] = True
                        result["keys"] = data
            else:
                result["error"] = f"获取失败，状态码: {response.status_code}"
                print(f"    {result['error']}")
                return result

        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            print(f"    请求错误: {e}")
            return result
        except json.JSONDecodeError as e:
            result["error"] = f"JSON解析错误: {e}"
            print(f"    {result['error']}")
            return result

    return result


def extract_form_data(html: str) -> dict:
    """
    从HTML中提取表单相关数据

    Args:
        html: HTML内容

    Returns:
        表单数据字典
    """
    form_data = {}

    # 提取 state
    state_match = re.search(r'name="state"\s+value="([^"]+)"', html)
    if state_match:
        form_data["state"] = state_match.group(1)

    # 提取其他隐藏字段
    hidden_fields = re.findall(r'<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"', html)
    for name, value in hidden_fields:
        form_data[name] = value

    # 也尝试反向匹配
    hidden_fields2 = re.findall(r'<input[^>]+name="([^"]+)"[^>]+type="hidden"[^>]+value="([^"]*)"', html)
    for name, value in hidden_fields2:
        if name not in form_data:
            form_data[name] = value

    return form_data


def _extract_primary_form_html(html: str) -> str:
    """
    提取页面中 primary form 的 HTML（避免抓到社交登录等其他表单字段）
    """
    if not html:
        return html

    m = re.search(
        r'(<form[^>]*data-form-primary="true"[^>]*>.*?</form>)',
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return m.group(1) if m else html


def _extract_action_value(html: str) -> str:
    m = re.search(r'<button[^>]+name="action"[^>]+value="([^"]+)"', html or "", re.IGNORECASE)
    return m.group(1) if m else "default"


def _extract_error_code(html: str) -> str | None:
    m = re.search(r'data-error-code="([^"]+)"', html or "", re.IGNORECASE)
    return m.group(1) if m else None


def submit_signup_step1(
    session: requests.Session,
    signup_url: str,
    email: str,
    captcha: str,
    state: str,
    html: str = None,
) -> dict:
    """
    提交注册第一步：邮箱和验证码

    Args:
        session: requests会话对象
        signup_url: 注册页面URL
        email: 邮箱地址
        captcha: 验证码
        state: state参数
        html: 已获取的注册页面HTML（可选，用于提取表单字段）

    Returns:
        提交结果
    """
    result = {
        "success": False,
        "response": None,
        "next_url": None,
        "error": None,
        "status_code": None,
    }

    print(f"\n[7] 提交注册表单...")
    print(f"    Email: {email}")
    print(f"    Captcha: {captcha}")

    # Auth0 的表单提交端点 - 使用完整URL包含state参数
    submit_url = signup_url

    # 构建表单数据（仅从 primary form 提取隐藏字段，避免误用社交登录的 connection 等字段）
    if html is None:
        try:
            page_resp = session.get(signup_url, timeout=30)
            html = page_resp.text if page_resp.status_code == 200 else None
        except Exception:
            html = None

    form_html = _extract_primary_form_html(html or "")
    extracted = extract_form_data(form_html)
    action_value = _extract_action_value(form_html)

    form_data = dict(extracted)
    form_data["state"] = extracted.get("state") or state
    form_data["email"] = email
    form_data["captcha"] = captcha
    form_data["action"] = action_value

    # 设置表单提交的请求头
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://auth.tavily.com",
        "Referer": signup_url,
        "Upgrade-Insecure-Requests": "1",
    }

    try:
        response = session.post(
            submit_url,
            data=form_data,
            headers=headers,
            allow_redirects=False
        )

        result["status_code"] = response.status_code
        print(f"    响应状态码: {response.status_code}")

        if response.status_code == 302:
            next_url = response.headers.get("Location", "")
            if next_url.startswith("/"):
                next_url = urljoin("https://auth.tavily.com", next_url)

            print(f"    重定向到: {next_url[:60]}...")

            # 检查是否进入下一步（设置密码）
            if "/u/signup/password" in next_url:
                result["success"] = True
                result["next_url"] = next_url
                print(f"    进入密码设置页面")
            else:
                result["next_url"] = next_url
                # 可能验证码错误，重定向回注册页面
                if "/u/signup/identifier" in next_url or "error" in next_url.lower():
                    result["error"] = "验证码可能错误，请重试"
                    print(f"    可能验证码错误")
                else:
                    result["success"] = True

        elif response.status_code == 200:
            # 返回200表示表单有错误，检查页面内容
            html = response.text
            if "captcha" in html.lower() and ("invalid" in html.lower() or "error" in html.lower() or "incorrect" in html.lower()):
                result["error"] = "验证码错误"
                print(f"    验证码错误")
            elif "already" in html.lower() and "registered" in html.lower():
                result["error"] = "邮箱已注册"
                print(f"    邮箱已注册")
            else:
                # 可能是其他表单错误
                result["error"] = "表单提交失败"
                print(f"    表单提交失败")
            result["response"] = response

        else:
            result["error"] = f"意外的响应状态码: {response.status_code}"
            print(f"    意外的响应状态码")

        result["response"] = response

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        print(f"    请求错误: {e}")

    return result


def submit_signup_password(session: requests.Session, password_url: str, password: str, state: str, email: str) -> dict:
    """
    提交注册第二步：设置密码

    Args:
        session: requests会话对象
        password_url: 密码设置页面URL
        password: 密码
        state: state参数
        email: 用户邮箱

    Returns:
        提交结果
    """
    result = {
        "success": False,
        "response": None,
        "error": None,
        "status_code": None,
        "error_code": None,
        "retryable": True,
    }

    print(f"\n[8] 设置密码...")

    # 先获取密码页面
    response = session.get(password_url)
    if response.status_code != 200:
        result["error"] = f"获取密码页面失败: {response.status_code}"
        return result

    # 提取state字段
    html = response.text
    extracted = extract_form_data(html)
    extracted_state = extracted.get("state") or state
    action_value = _extract_action_value(html)

    form_data = dict(extracted)
    form_data["state"] = extracted_state
    form_data["email"] = email
    form_data["password"] = password
    form_data["action"] = action_value

    # 使用完整的password_url（包含state参数）作为提交URL
    submit_url = password_url
    print(f"    提交URL: {submit_url[:60]}...")
    print(f"    表单字段: {list(form_data.keys())}")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://auth.tavily.com",
        "Referer": password_url,
    }

    try:
        response = session.post(
            submit_url,
            data=form_data,
            headers=headers,
            allow_redirects=False
        )

        result["status_code"] = response.status_code
        print(f"    响应状态码: {response.status_code}")

        if response.status_code == 302:
            next_url = response.headers.get("Location", "")
            if next_url.startswith("/"):
                next_url = urljoin("https://auth.tavily.com", next_url)
            print(f"    重定向到: {next_url[:60]}...")
            result["success"] = True
            result["next_url"] = next_url
        else:
            result["error_code"] = _extract_error_code(response.text)
            if result["error_code"] and response.status_code in (400, 422):
                result["retryable"] = False
            if result["error_code"]:
                result["error"] = f"密码设置失败: {result['error_code']}"
            else:
                result["error"] = f"密码设置失败，状态码: {response.status_code}"
            result["response"] = response.text

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        print(f"    请求错误: {e}")

    return result


def signup(
    email: str,
    password: str = None,
    config: dict = None,
    max_retries: int = 3,
    mail_api_base: str = None,
    mail_jwt: str = None,
    keep_session: bool = False,
    *,
    debug_init: bool = False,
) -> dict:
    """
    完整的注册流程

    Args:
        email: 注册邮箱
        password: 密码（可选，如果不提供则只完成第一步）
        config: 配置字典
        max_retries: 验证码识别最大重试次数
        mail_api_base: 临时邮箱API基础地址（用于接收验证邮件）
        mail_jwt: 临时邮箱JWT令牌

    Returns:
        注册结果
    """
    if config is None:
        config = load_config()

    result = {
        "success": False,
        "email": email,
        "error": None,
        "step": 0,
        "api_keys": None,
        "session": None,
    }

    for attempt in range(max_retries):
        print(f"\n{'='*60}")
        print(f"注册尝试 {attempt + 1}/{max_retries}")
        print(f"{'='*60}")

        session = create_session()
        keep_open = False
        try:

            # Step 1: 获取注册页面
            signup_info = get_signup_page(session)
            if not signup_info["success"]:
                result["error"] = "获取注册页面失败"
                continue

            # Step 2: 获取页面和验证码
            page_info = fetch_page_with_captcha(session, signup_info["signup_url"])
            if not page_info["success"]:
                result["error"] = "获取验证码失败"
                continue

            if not page_info["captcha_base64"]:
                result["error"] = "未找到验证码"
                continue

            # Step 3: 识别验证码
            captcha_text = recognize_captcha_with_vision(page_info["captcha_base64"], config)
            if not captcha_text:
                result["error"] = "验证码识别失败"
                continue

            # Step 4: 提交注册表单
            submit_result = submit_signup_step1(
                session,
                signup_info["signup_url"],
                email,
                captcha_text,
                signup_info["state"],
                html=page_info.get("html"),
            )

            if submit_result["success"]:
                result["step"] = 1
                print(f"\n注册第一步完成!")

                # 如果提供了密码，继续设置密码
                if password and submit_result.get("next_url"):
                    password_result = submit_signup_password(
                        session,
                        submit_result["next_url"],
                        password,
                        signup_info["state"],
                        email
                    )

                    if password_result["success"]:
                        result["step"] = 2
                        print(f"\n密码设置完成!")

                        # 如果提供了邮箱API配置，继续完成邮箱验证
                        if mail_api_base and mail_jwt:
                            verification_link = wait_for_verification_email(
                                mail_api_base, mail_jwt, timeout=120, poll_interval=5
                            )

                            if verification_link:
                                verify_result = verify_email(session, verification_link)
                                if verify_result["success"]:
                                    result["step"] = 3
                                    print(f"\n邮箱验证完成!")

                                    # 检查是否已经登录（验证后跳转到app.tavily.com）
                                    final_url = verify_result.get("final_url", "")
                                    already_logged_in = "app.tavily.com" in final_url

                                    # 有些情况下 verify_email 最终停留在 auth 域名，但同一会话 cookie
                                    # 已可用于进入 app；这里再触发一次登录回调以尽量避免二次过验证码。
                                    if not already_logged_in:
                                        try:
                                            resp = session.get(
                                                "https://app.tavily.com/api/auth/login?returnTo=/home",
                                                allow_redirects=True,
                                                timeout=30,
                                            )
                                            if "app.tavily.com" in (resp.url or ""):
                                                already_logged_in = True
                                        except Exception:
                                            pass

                                    session_valid = False
                                    try:
                                        resp = session.get("https://app.tavily.com/api/auth/me", timeout=30)
                                        session_valid = resp.status_code == 200
                                    except Exception:
                                        session_valid = False

                                    if already_logged_in and session_valid:
                                        print(f"    验证后已建立登录态，优先用当前 session 获取 key")
                                        result["step"] = 4

                                        keys_result = get_api_keys(session, max_retries=10, retry_delay=2, debug_init=debug_init)
                                        if keys_result["success"] and keys_result.get("keys"):
                                            keys = keys_result["keys"]
                                            has_key = False
                                            if isinstance(keys, list) and len(keys) > 0:
                                                has_key = any((k.get("key") or k.get("api_key") or k.get("apiKey")) for k in keys if isinstance(k, dict))
                                            elif isinstance(keys, dict) and (keys.get("key") or keys.get("api_key") or keys.get("apiKey")):
                                                has_key = True

                                            if has_key:
                                                result["step"] = 5
                                                result["api_keys"] = keys_result["keys"]
                                                result["success"] = True
                                                print(f"\n注册全部完成!")
                                                if keep_session:
                                                    result["session"] = session
                                                    keep_open = True
                                                return result

                                        print(f"    未获取到API Key，尝试重新登录...")

                                    # 登录账户 (最多重试3次)
                                    for login_attempt in range(3):
                                        login_result = login_after_verification(session, email, password, config)
                                        if login_result["success"]:
                                            result["step"] = 4
                                            print(f"\n登录完成!")

                                            # 获取API Keys（注册成功后会自动生成）
                                            keys_result = get_api_keys(session, max_retries=10, retry_delay=2, debug_init=debug_init)
                                            if keys_result["success"]:
                                                keys = keys_result.get("keys")
                                                has_key = False
                                                if isinstance(keys, list) and len(keys) > 0:
                                                    has_key = any((k.get("key") or k.get("api_key") or k.get("apiKey")) for k in keys if isinstance(k, dict))
                                                elif isinstance(keys, dict) and (keys.get("key") or keys.get("api_key") or keys.get("apiKey")):
                                                    has_key = True

                                                if has_key:
                                                    result["step"] = 5
                                                    result["api_keys"] = keys_result["keys"]
                                                    result["success"] = True
                                                    print(f"\n注册全部完成!")
                                                    if keep_session:
                                                        result["session"] = session
                                                        keep_open = True
                                                    return result
                                                else:
                                                    result["error"] = "API Key未生成"
                                                    result["success"] = True  # 注册成功但key未生成
                                                    result["step"] = 5
                                                    if keep_session:
                                                        result["session"] = session
                                                        keep_open = True
                                                    return result
                                            else:
                                                result["error"] = keys_result.get("error", "获取API Keys失败")
                                                return result  # 登录成功但获取key失败，直接返回
                                        else:
                                            print(f"    登录尝试 {login_attempt + 1}/3 失败: {login_result.get('error')}")
                                            if login_attempt < 2:
                                                print(f"    重试登录...")

                                    # 所有登录尝试都失败
                                    result["error"] = login_result.get("error", "登录失败")
                                    return result  # 邮箱已验证，不再重试注册
                                else:
                                    result["error"] = verify_result.get("error", "邮箱验证失败")
                                    return result  # 验证失败，直接返回
                            else:
                                result["error"] = "未收到验证邮件"
                                # 未收到邮件可以重试
                        else:
                            result["success"] = True
                            print(f"\n注册完成! (未进行邮箱验证)")
                            if keep_session:
                                result["session"] = session
                                keep_open = True
                            return result
                    else:
                        result["error"] = password_result.get("error", "密码设置失败")
                        if password_result.get("retryable") is False:
                            return result
                else:
                    result["success"] = True
                    if keep_session:
                        result["session"] = session
                        keep_open = True
                    return result

            else:
                result["error"] = submit_result.get("error", "注册失败")
                print(f"    注册失败: {result['error']}")
        finally:
            if not keep_open:
                try:
                    session.close()
                except Exception:
                    pass

    return result


