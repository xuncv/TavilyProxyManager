"""
Tavily 批量注册
使用 GPTMail 临时邮箱自动生成邮箱，批量注册并保存 API Key
"""
import argparse
import os
import time
from datetime import datetime
from typing import Iterable

from gptmail_client import GPTMailAPIError, GPTMailClient
from signup import (
    create_session,
    create_api_key,
    get_api_keys,
    load_config,
    login_after_verification,
    signup,
    verify_email,
)

# 配置
OUTPUT_FILE = "api_keys.txt"
FAILED_FILE = "failed.txt"
BANNED_DOMAINS_FILE = "banned_domains.txt"
PASSWORD = "Tavily@2024Test"

# 注册间隔（秒），避免被限制
REGISTER_INTERVAL = 5
VERIFY_TIMEOUT = 180
VERIFY_POLL_INTERVAL = 5.0
MAX_EMAIL_GENERATE_ATTEMPTS = 30
MAX_DOMAIN_BLOCKED_RETRIES = 10


def _extract_key_value(item) -> str:
    if isinstance(item, dict):
        return item.get("key") or item.get("api_key") or item.get("apiKey") or ""
    return ""


def _extract_first_api_key(keys) -> str | None:
    if isinstance(keys, list):
        for item in keys:
            v = _extract_key_value(item)
            if v:
                return v
        return None
    if isinstance(keys, dict):
        v = _extract_key_value(keys)
        return v or None
    if isinstance(keys, str):
        v = keys.strip()
        return v or None
    return None


def save_result(file_path: str, email: str, api_key: str, mode: str = 'a'):
    """保存结果到文件"""
    with open(file_path, mode, encoding='utf-8') as f:
        f.write(f"{email}----{api_key}\n")


def save_failed(file_path: str, email: str, error: str, mode: str = 'a'):
    """保存失败记录"""
    with open(file_path, mode, encoding='utf-8') as f:
        f.write(f"{email}----{error}\n")


def load_email_list(file_path: str) -> list[str]:
    """
    加载邮箱列表文件。

    支持:
      - 每行一个邮箱
      - email----... (只取第一段邮箱，兼容旧 failed.txt / email.txt)
    """
    out: list[str] = []
    if not file_path:
        return out
    if not os.path.exists(file_path):
        print(f"错误: 文件不存在 {file_path}")
        return out

    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            email = line.split("----", 1)[0].strip()
            if "@" not in email:
                print(f"警告: 第 {line_num} 行不是邮箱，跳过: {line[:80]}")
                continue
            out.append(email)

    return out


def extract_domain(email: str) -> str | None:
    if not email or "@" not in email:
        return None
    domain = email.split("@", 1)[1].strip().lower()
    return domain or None


def load_banned_domains(file_path: str) -> set[str]:
    domains: set[str] = set()
    if not file_path or not os.path.exists(file_path):
        return domains

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.add(line.lower())
    return domains


def add_banned_domain(file_path: str, domain: str, banned_domains: set[str]) -> bool:
    domain = (domain or "").strip().lower()
    if not domain:
        return False
    if domain in banned_domains:
        return False

    banned_domains.add(domain)
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(f"{domain}\n")
    return True


def generate_unbanned_email(
    client: GPTMailClient,
    banned_domains: set[str],
    *,
    prefix: str | None = None,
    domain: str | None = None,
    max_attempts: int = MAX_EMAIL_GENERATE_ATTEMPTS,
) -> str:
    if domain and domain.strip().lower() in banned_domains:
        raise ValueError(f"指定域名已被禁用: {domain}")

    for _ in range(max_attempts):
        email = client.generate_email(prefix=prefix, domain=domain)
        d = extract_domain(email)
        if d and d in banned_domains:
            print(f"    命中禁用域名 {d}，重新获取邮箱...")
            continue
        return email

    raise RuntimeError(f"生成邮箱失败: 连续 {max_attempts} 次命中禁用域名")


def try_login_get_key(email: str, password: str, config: dict, *, debug_init: bool = False) -> str:
    """
    尝试登录已注册账户并获取API Key

    Returns:
        API Key 或 None
    """
    print(f"    尝试登录获取API Key...")
    max_login_attempts = 5
    session = None
    for attempt in range(max_login_attempts):
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

        session = create_session()
        try:
            login_result = login_after_verification(session, email, password, config)
            if login_result.get("success"):
                # 获取API Keys
                keys_result = get_api_keys(session, max_retries=10, retry_delay=2, debug_init=debug_init)
                if keys_result.get("success") and keys_result.get("keys"):
                    keys = keys_result["keys"]
                    if isinstance(keys, list) and len(keys) > 0:
                        api_key = _extract_key_value(keys[0])
                        if api_key:
                            return api_key
                    elif isinstance(keys, dict):
                        api_key = _extract_key_value(keys)
                        if api_key:
                            return api_key

                # 登录成功但没有 key，尝试创建
                print(f"    登录成功但没有 key，尝试创建...")
                try:
                    create_result = create_api_key(session, key_name="default")
                    if create_result.get("success") and create_result.get("key"):
                        api_key = _extract_first_api_key(create_result["key"])
                        if api_key:
                            return api_key
                        # 创建返回成功但 key 为空，打印警告
                        print(f"    警告: 创建 key 返回成功但 key 为空: {create_result.get('key')}")
                    else:
                        print(f"    创建 key 失败: {create_result.get('error')}")
                except Exception as e:
                    print(f"    创建 key 异常: {e}")
                return None

            error_code = login_result.get("error_code")
            print(f"    登录失败: {login_result.get('error')}")
            if error_code == "invalid-captcha" and attempt < max_login_attempts - 1:
                print(f"    验证码错误，重试登录 ({attempt + 2}/{max_login_attempts})...")
                time.sleep(2)
                continue
            # 其他错误也重试（如网络问题）
            if attempt < max_login_attempts - 1:
                print(f"    重试登录 ({attempt + 2}/{max_login_attempts})...")
                time.sleep(2)
                continue
            return None
        finally:
            try:
                session.close()
            except Exception:
                pass

    return None


def _verify_with_gptmail_and_get_key(
    client: GPTMailClient,
    email: str,
    password: str,
    config: dict,
    *,
    session=None,
    verify_timeout: int = VERIFY_TIMEOUT,
    verify_poll_interval: float = VERIFY_POLL_INTERVAL,
    debug_init: bool = False,
) -> str | None:
    print(f"    等待 GPTMail 验证邮件...")
    link = client.wait_for_verification_link(email, timeout=verify_timeout, poll_interval=verify_poll_interval)
    if not link:
        print(f"    超时: 未收到验证邮件")
        return None

    print(f"    获取到验证链接: {link[:60]}...")

    close_session = False
    if session is None:
        session = create_session()
        close_session = True
    try:
        verify_result = verify_email(session, link)
        if not verify_result.get("success"):
            print(f"    邮箱验证失败: {verify_result.get('error')}")
            return None

        # 尝试复现浏览器行为：验证后通常会直接进入登录态（同一会话 cookie）
        # 即便 verify_email 最终停留在 auth 域名，也再"触发一次登录回调"以获取 app 会话。
        try:
            resp = session.get("https://app.tavily.com/api/auth/login?returnTo=/home", allow_redirects=True, timeout=30)
            if "app.tavily.com" in (resp.url or ""):
                print("    已进入应用(登录态已建立)")
        except Exception:
            pass

        # 检查 session 是否有效（关键步骤！）
        session_valid = False
        try:
            resp = session.get("https://app.tavily.com/api/auth/me", timeout=30)
            if resp.status_code == 200:
                print(f"    获取用户资料成功：{resp.json()}")
                session_valid = True
            else:
                print(f"    Session 无效 (status={resp.status_code})，需要重新登录")
        except Exception as e:
            print(f"    检查 session 失败: {e}")

        # 如果 session 无效，直接尝试登录获取
        if not session_valid:
            print("    验证完成但未建立登录态，尝试登录...")
            return try_login_get_key(email, password, config, debug_init=debug_init)

        # 验证后优先尝试直接获取 key，避免再次过验证码登录
        keys_result = get_api_keys(session, max_retries=10, retry_delay=2, debug_init=debug_init)
        if keys_result.get("success") and keys_result.get("keys"):
            api_key = _extract_first_api_key(keys_result["keys"])
            if api_key:
                return api_key

        # 部分情况下默认 key 生成较慢；若已登录但 /api/keys 仍为空，直接创建一个新 key
        try:
            create_result = create_api_key(session, key_name="default")
            if create_result.get("success") and create_result.get("key"):
                api_key = _extract_first_api_key(create_result["key"])
                if api_key:
                    return api_key
        except Exception:
            pass

        # 如果到这里还没获取到 key，尝试重新登录
        print("    已登录但未获取到 key，尝试重新登录...")
        return try_login_get_key(email, password, config, debug_init=debug_init)
    finally:
        if close_session:
            try:
                session.close()
            except Exception:
                pass


def batch_signup(
    *,
    count: int = 1,
    output_file: str = OUTPUT_FILE,
    failed_file: str = FAILED_FILE,
    banned_domains_file: str = BANNED_DOMAINS_FILE,
    password: str = PASSWORD,
    interval: int = REGISTER_INTERVAL,
    gptmail_base_url: str | None = None,
    gptmail_api_key: str | None = None,
    gptmail_timeout: float = 30.0,
    gptmail_prefix: str | None = None,
    gptmail_domain: str | None = None,
    emails: Iterable[str] | None = None,
    verify_timeout: int = VERIFY_TIMEOUT,
    verify_poll_interval: float = VERIFY_POLL_INTERVAL,
    max_generate_attempts: int = MAX_EMAIL_GENERATE_ATTEMPTS,
    debug_init: bool = False,
):
    """
    批量注册
    """
    print("=" * 60)
    print("Tavily 批量注册")
    print("=" * 60)
    print(f"输出文件: {output_file}")
    print(f"失败记录: {failed_file}")
    print()

    # 加载配置
    config = load_config()

    email_list = list(emails) if emails is not None else []
    if emails is None:
        if count <= 0:
            print("count 必须大于 0")
            return
        print(f"注册数量: {count}")
    else:
        if not email_list:
            print("没有找到有效的邮箱记录")
            return
        print(f"共加载 {len(email_list)} 个邮箱")
    print()

    # 统计
    success_count = 0
    failed_count = 0
    skipped_count = 0

    banned_domains = load_banned_domains(banned_domains_file)
    if banned_domains:
        print(f"禁用域名: {len(banned_domains)} (来自 {banned_domains_file})")
        print()

    # 检查已注册的邮箱（从输出文件读取）
    registered_emails = set()
    if os.path.exists(output_file):
        with open(output_file, 'r', encoding='utf-8') as f:
            for line in f:
                if '----' in line:
                    email = line.split('----')[0].strip()
                    registered_emails.add(email)
        if registered_emails:
            print(f"已有 {len(registered_emails)} 个邮箱注册成功，将跳过")
            print()

    if not gptmail_base_url:
        gptmail_base_url = os.environ.get("GPTMAIL_BASE_URL", "https://mail.chatgpt.org.uk")
    if not gptmail_api_key:
        gptmail_api_key = os.environ.get("GPTMAIL_API_KEY", "gpt-test")

    # 开始注册
    start_time = datetime.now()

    total = len(email_list) if emails is not None else count

    with GPTMailClient(gptmail_base_url, gptmail_api_key, timeout=gptmail_timeout) as mail_client:
        for i in range(total):
            domain_blocked_retries = 0
            while True:
                if emails is None:
                    try:
                        email = generate_unbanned_email(
                            mail_client,
                            banned_domains,
                            prefix=gptmail_prefix,
                            domain=gptmail_domain,
                            max_attempts=max_generate_attempts,
                        )
                    except (GPTMailAPIError, ValueError, RuntimeError) as e:
                        err = f"gptmail_generate_failed: {e}"
                        print(f"\n{'='*60}")
                        print(f"[{i+1}/{total}] (生成邮箱失败)")
                        print(f"{'='*60}")
                        print(err)
                        save_failed(failed_file, "N/A", err)
                        failed_count += 1
                        break
                else:
                    email = email_list[i]

                print(f"\n{'='*60}")
                print(f"[{i+1}/{total}] {email}")
                print(f"{'='*60}")

                # 检查是否已注册
                if email in registered_emails:
                    print(f"跳过: 已注册")
                    skipped_count += 1
                    if emails is None:
                        # 自动生成模式：继续生成新邮箱，保证最终注册数量接近 count
                        continue
                    break

                try:
                    # 执行注册 (先完成到设置密码；验证邮件通过 GPTMail 获取)
                    result = signup(
                        email=email,
                        password=password,
                        config=config,
                        max_retries=3,
                        mail_api_base=None,
                        mail_jwt=None,
                        keep_session=True,
                        debug_init=debug_init,
                    )

                    signup_session = result.get("session")
                    try:
                        if result.get("success") and result.get("api_keys"):
                            api_key = _extract_first_api_key(result.get("api_keys"))
                            if api_key:
                                save_result(output_file, email, api_key)
                                print(f"\n成功! API Key: {api_key[:15]}...{api_key[-4:]}")
                                success_count += 1
                                break

                        if result.get("success"):
                            # 注册/设置密码完成，开始邮箱验证 -> 获取 key
                            api_key = _verify_with_gptmail_and_get_key(
                                mail_client,
                                email,
                                password,
                                config,
                                session=signup_session,
                                verify_timeout=verify_timeout,
                                verify_poll_interval=verify_poll_interval,
                                debug_init=debug_init,
                            )
                            if api_key:
                                save_result(output_file, email, api_key)
                                print(f"\n成功! API Key: {api_key[:15]}...{api_key[-4:]}")
                                success_count += 1
                            else:
                                save_failed(failed_file, email, f"no_api_key_after_verify_step_{result.get('step')}")
                                print(f"\n注册完成但未获取到 API Key")
                                failed_count += 1
                            break

                        # 注册失败 - 可能邮箱已注册，尝试登录获取API Key
                        error = result.get("error", "unknown")
                        print(f"\n注册失败: {error}")

                        # IP 被禁止：立即终止批量注册
                        if isinstance(error, str) and "ip-signup-blocked" in error:
                            save_failed(failed_file, email, error)
                            print("\n检测到 ip-signup-blocked：当前 IP 已被禁止，终止批量注册。")
                            return

                        # 域名被禁用：加入禁用列表并重新获取邮箱注册（仅自动生成模式）
                        if (
                            isinstance(error, str)
                            and "custom-script-error-code_extensibility_error" in error
                            and "密码设置失败" in error
                        ):
                            d = extract_domain(email)
                            if d and add_banned_domain(banned_domains_file, d, banned_domains):
                                print(f"    已加入禁用域名: {d}")

                            if emails is None:
                                domain_blocked_retries += 1
                                if domain_blocked_retries > MAX_DOMAIN_BLOCKED_RETRIES:
                                    save_failed(failed_file, email, error)
                                    print(f"\n域名被禁用，已重试 {MAX_DOMAIN_BLOCKED_RETRIES} 次仍失败，放弃该条。")
                                    failed_count += 1
                                    break
                                print("    域名邮箱被禁止，重新获取邮箱重试...")
                                if interval > 0:
                                    print(f"    等待 {interval} 秒...")
                                    time.sleep(interval)
                                continue

                            # 输入邮箱列表模式无法更换邮箱：记录失败后继续下一条
                            save_failed(failed_file, email, error)
                            print(f"\n最终失败: {error}")
                            failed_count += 1
                            break

                        # 尝试登录获取API Key（邮箱可能已经注册）
                        api_key = try_login_get_key(email, password, config, debug_init=debug_init)
                        if api_key:
                            save_result(output_file, email, api_key)
                            print(f"\n通过登录获取成功! API Key: {api_key[:15]}...{api_key[-4:]}")
                            success_count += 1
                        else:
                            save_failed(failed_file, email, error)
                            print(f"\n最终失败: {error}")
                            failed_count += 1
                        break
                    finally:
                        if signup_session is not None:
                            try:
                                signup_session.close()
                            except Exception:
                                pass

                except Exception as e:
                    save_failed(failed_file, email, str(e))
                    print(f"\n异常: {e}")
                    failed_count += 1
                    break

            # 注册间隔
            if i < total - 1:
                print(f"\n等待 {interval} 秒...")
                time.sleep(interval)

    # 统计结果
    end_time = datetime.now()
    duration = end_time - start_time

    print()
    print("=" * 60)
    print("批量注册完成")
    print("=" * 60)
    print(f"总数: {total}")
    print(f"成功: {success_count}")
    print(f"失败: {failed_count}")
    print(f"跳过: {skipped_count}")
    print(f"耗时: {duration}")
    print()
    print(f"API Keys 已保存到: {output_file}")
    if failed_count > 0:
        print(f"失败记录已保存到: {failed_file}")


def retry_failed(
    *,
    failed_file: str = FAILED_FILE,
    output_file: str = OUTPUT_FILE,
    banned_domains_file: str = BANNED_DOMAINS_FILE,
    password: str = PASSWORD,
    interval: int = REGISTER_INTERVAL,
    gptmail_base_url: str | None = None,
    gptmail_api_key: str | None = None,
    gptmail_timeout: float = 30.0,
    verify_timeout: int = VERIFY_TIMEOUT,
    verify_poll_interval: float = VERIFY_POLL_INTERVAL,
    debug_init: bool = False,
):
    """
    重试失败的注册
    """
    print("=" * 60)
    print("重试失败的注册")
    print("=" * 60)

    if not os.path.exists(failed_file):
        print(f"没有失败记录: {failed_file}")
        return

    emails = load_email_list(failed_file)
    if not emails:
        print("没有需要重试的记录")
        return

    print(f"找到 {len(emails)} 条失败记录")

    # 清空失败文件
    open(failed_file, 'w').close()

    # 重新注册
    batch_signup(
        emails=emails,
        output_file=output_file,
        failed_file=failed_file,
        banned_domains_file=banned_domains_file,
        password=password,
        interval=interval,
        gptmail_base_url=gptmail_base_url,
        gptmail_api_key=gptmail_api_key,
        gptmail_timeout=gptmail_timeout,
        verify_timeout=verify_timeout,
        verify_poll_interval=verify_poll_interval,
        debug_init=debug_init,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Tavily 批量注册 (GPTMail)')
    parser.add_argument('--retry', action='store_true', help='重试失败的注册')
    parser.add_argument('--count', '-n', type=int, default=1, help='注册数量 (不指定 --input 时使用)')
    parser.add_argument('--input', '-i', default=None, help='邮箱列表文件 (每行一个邮箱，或 email----... 只取邮箱)')
    parser.add_argument('--output', '-o', default=OUTPUT_FILE, help='输出文件路径')
    parser.add_argument('--failed', default=FAILED_FILE, help='失败记录文件路径')
    parser.add_argument('--banned-domains', default=BANNED_DOMAINS_FILE, help='禁用域名列表文件路径')
    parser.add_argument('--password', default=PASSWORD, help='注册/登录密码')
    parser.add_argument('--interval', type=int, default=REGISTER_INTERVAL, help='注册间隔 (秒)')

    parser.add_argument('--gptmail-base-url', default=os.environ.get("GPTMAIL_BASE_URL", "https://mail.chatgpt.org.uk"))
    parser.add_argument('--gptmail-api-key', default=os.environ.get("GPTMAIL_API_KEY", "gpt-test"))
    parser.add_argument('--gptmail-timeout', type=float, default=float(os.environ.get("GPTMAIL_TIMEOUT", "30")))
    parser.add_argument('--gptmail-prefix', default=os.environ.get("GPTMAIL_PREFIX"))
    parser.add_argument('--gptmail-domain', default=os.environ.get("GPTMAIL_DOMAIN"))
    parser.add_argument('--max-generate-attempts', type=int, default=MAX_EMAIL_GENERATE_ATTEMPTS, help='生成邮箱最大重试次数(遇到禁用域名时)')
    parser.add_argument('--verify-timeout', type=int, default=VERIFY_TIMEOUT)
    parser.add_argument('--verify-interval', type=float, default=VERIFY_POLL_INTERVAL)
    parser.add_argument('--debug-init', action='store_true', help='打印首次登录初始化接口调用信息（/api/account 等）')

    args = parser.parse_args()

    if args.retry:
        retry_failed(
            failed_file=args.failed,
            output_file=args.output,
            banned_domains_file=args.banned_domains,
            password=args.password,
            interval=args.interval,
            gptmail_base_url=args.gptmail_base_url,
            gptmail_api_key=args.gptmail_api_key,
            gptmail_timeout=args.gptmail_timeout,
            verify_timeout=args.verify_timeout,
            verify_poll_interval=args.verify_interval,
            debug_init=args.debug_init,
        )
    else:
        emails = load_email_list(args.input) if args.input else None
        batch_signup(
            count=args.count,
            emails=emails,
            output_file=args.output,
            failed_file=args.failed,
            banned_domains_file=args.banned_domains,
            password=args.password,
            interval=args.interval,
            gptmail_base_url=args.gptmail_base_url,
            gptmail_api_key=args.gptmail_api_key,
            gptmail_timeout=args.gptmail_timeout,
            gptmail_prefix=(args.gptmail_prefix or None),
            gptmail_domain=(args.gptmail_domain or None),
            verify_timeout=args.verify_timeout,
            verify_poll_interval=args.verify_interval,
            max_generate_attempts=args.max_generate_attempts,
            debug_init=args.debug_init,
        )
