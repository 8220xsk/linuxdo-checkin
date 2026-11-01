"""
cron: 0 */6 * * *
new Env("Linux.Do 签到")
"""

import os
import json
import random
import time
import functools
from loguru import logger
from DrissionPage import ChromiumOptions, Chromium
from tabulate import tabulate
from curl_cffi import requests
from notify import NotificationManager


def retry_decorator(retries=3, min_delay=5, max_delay=10):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == retries - 1:  # 最后一次尝试
                        logger.error(f"函数 {func.__name__} 最终执行失败: {str(e)}")
                    logger.warning(
                        f"函数 {func.__name__} 第 {attempt + 1}/{retries} 次尝试失败: {str(e)}"
                    )
                    if attempt < retries - 1:
                        sleep_s = random.uniform(min_delay, max_delay)
                        logger.info(
                            f"将在 {sleep_s:.2f}s 后重试 ({min_delay}-{max_delay}s 随机延迟)"
                        )
                        time.sleep(sleep_s)
            return None

        return wrapper

    return decorator


os.environ.pop("DISPLAY", None)
os.environ.pop("DYLD_LIBRARY_PATH", None)

USERNAME = os.environ.get("LINUXDO_USERNAME")
PASSWORD = os.environ.get("LINUXDO_PASSWORD")
COOKIES = os.environ.get("LINUXDO_COOKIES", "").strip()  # 手动设置的 Cookie 字符串，优先使用
YESCAPTCHA_CLIENT_KEY = os.environ.get("YESCAPTCHA_CLIENT_KEY", "").strip()  # YesCaptcha 的 clientKey，用于过登录 hCaptcha
YESCAPTCHA_API_BASE = os.environ.get("YESCAPTCHA_API_BASE", "https://api.yescaptcha.com").strip().rstrip("/")
BROWSE_ENABLED = os.environ.get("BROWSE_ENABLED", "true").strip().lower() not in [
    "false",
    "0",
    "off",
]
if not USERNAME:
    USERNAME = os.environ.get("USERNAME")
if not PASSWORD:
    PASSWORD = os.environ.get("PASSWORD")

HOME_URL = "https://linux.do/"
LOGIN_URL = "https://linux.do/login"
SESSION_URL = "https://linux.do/session"
CSRF_URL = "https://linux.do/session/csrf"
CAPTCHA_VERIFY_URL = "https://linux.do/captcha/hcaptcha/create.json"
HCAPTCHA_WEBSITE_KEY = "a776b4ac-8c4c-441e-986a-c6ee9ed8cf08"  # linux.do 登录 hCaptcha sitekey
# CF 对各浏览器指纹的拦截随时间波动（实测同一天 chrome151 和 firefox155 轮流被拦），
# 按顺序尝试，谁没被拦就用谁，并记住供后续请求复用
# 注：curl_cffi 指纹永远滞后于真实浏览器（当前真实 Chrome 155 / Firefox 159），
# "chrome"/"firefox" 别名 = 其内置最新版，升级 curl-cffi 即自动跟上
FALLBACK_IMPERSONATES = ["chrome", "chrome152", "firefox", "firefox155", "chrome151"]
# 登录成功后的 Cookie 缓存文件，下次运行直接复用，避免每次都过验证码
COOKIE_CACHE = os.environ.get(
    "LINUXDO_COOKIE_CACHE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "linuxdo_cookies.json"),
)


class LinuxDoBrowser:
    def __init__(self) -> None:
        from sys import platform

        if platform == "linux" or platform == "linux2":
            platformIdentifier = "X11; Linux x86_64"
        elif platform == "darwin":
            platformIdentifier = "Macintosh; Intel Mac OS X 10_15_7"
        elif platform == "win32":
            platformIdentifier = "Windows NT 10.0; Win64; x64"
        else:
            platformIdentifier = "X11; Linux x86_64"

        co = (
            ChromiumOptions()
            .headless(True)
            .incognito(True)
            .set_argument("--no-sandbox")
        )
        co.set_user_agent(
            f"Mozilla/5.0 ({platformIdentifier}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        )
        self.browser = Chromium(co)
        self.page = self.browser.new_tab()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )
        # 初始化通知管理器
        self.notifier = NotificationManager()
        self._impersonate = FALLBACK_IMPERSONATES[0]  # 当前可用的 CF 指纹
        self.username = None  # 登录后从 current.json 取，用于读取用户统计
        self._csrf_token = None  # 懒加载，点赞等写操作前获取

    def get_with_cf_fallback(self, url, headers=None, timeout=30):
        """GET 请求带指纹降级：被 CF 拦截（Just a moment）时换下一个指纹重试"""
        candidates = [self._impersonate] + [f for f in FALLBACK_IMPERSONATES if f != self._impersonate]
        resp = None
        for imp in candidates:
            resp = self.session.get(url, headers=headers, impersonate=imp, timeout=timeout)
            if resp.status_code == 200 or "Just a moment" not in resp.text:
                self._impersonate = imp
                return resp
            logger.warning(f"指纹 {imp} 被 CF 拦截，切换下一个重试")
        return resp

    @staticmethod
    def parse_cookie_string(cookie_str: str) -> list[dict]:
        """
        解析浏览器复制的 Cookie 字符串格式: "name1=value1; name2=value2"
        返回 DrissionPage 所需的 cookie 列表格式。
        """
        cookies = []
        for part in cookie_str.strip().split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies.append(
                    {
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": ".linux.do",
                        "path": "/",
                    }
                )
        return cookies

    def login_with_cookies(self, cookie_str: str) -> bool:
        """使用手动设置的 Cookie 直接登录，跳过账号密码流程"""
        logger.info("检测到手动 Cookie，尝试 Cookie 登录...")
        dp_cookies = self.parse_cookie_string(cookie_str)
        if not dp_cookies:
            logger.error("Cookie 解析失败或为空，无法使用 Cookie 登录")
            return False

        logger.info(f"成功解析 {len(dp_cookies)} 个 Cookie 条目")

        # 同步到 requests.Session，以便后续 API 请求（如 print_connect_info）使用
        for ck in dp_cookies:
            self.session.cookies.set(ck["name"], ck["value"], domain="linux.do")

        # 同步到 DrissionPage
        self.page.set.cookies(dp_cookies)
        logger.info("Cookie 设置完成，导航至 linux.do...")
        self.page.get(HOME_URL)
        time.sleep(5)

        # 验证登录状态
        try:
            user_ele = self.page.ele("@id=current-user")
        except Exception as e:
            logger.warning(f"Cookie 登录验证异常: {str(e)}")
            return True
        if not user_ele:
            if "avatar" in self.page.html:
                logger.info("Cookie 登录验证成功 (通过 avatar)")
                return True
            logger.error("Cookie 登录验证失败 (未找到 current-user)，Cookie 可能已过期")
            return False
        else:
            logger.info("Cookie 登录验证成功")
            return True

    def solve_hcaptcha(self):
        """通过 YesCaptcha 解决 linux.do 登录的 hCaptcha，返回 (token, userAgent) 或 (None, None)"""
        if not YESCAPTCHA_CLIENT_KEY:
            logger.error("未设置 YESCAPTCHA_CLIENT_KEY，无法通过登录人机验证")
            return None, None

        logger.info("通过 YesCaptcha 解决 hCaptcha...")

        def _call(method, payload):
            resp = requests.post(
                f"{YESCAPTCHA_API_BASE}/{method}",
                json={"clientKey": YESCAPTCHA_CLIENT_KEY, **payload},
                timeout=30,
            )
            data = resp.json()
            if data.get("errorId"):
                raise RuntimeError(f"{data.get('errorCode')}: {data.get('errorDescription')}")
            return data

        task = {
            "type": "HCaptchaTaskProxyless",
            "websiteURL": LOGIN_URL,
            "websiteKey": HCAPTCHA_WEBSITE_KEY,
        }
        try:
            task_id = _call("createTask", {"task": task})["taskId"]
            logger.info(f"createTask 成功, taskId: {task_id}")
            for _ in range(36):  # 每 5 秒查询一次，最多约 3 分钟
                time.sleep(5)
                result = _call("getTaskResult", {"taskId": task_id})
                if result.get("status") == "ready":
                    solution = result["solution"]
                    token = solution["gRecaptchaResponse"]
                    ua = solution.get("userAgent")
                    logger.info(f"hCaptcha 解决成功 (token 长度 {len(token)})")
                    return token, ua
            logger.error("YesCaptcha 解题超时")
            return None, None
        except Exception as e:
            logger.error(f"YesCaptcha 请求异常: {e}")
            return None, None

    def try_cached_login(self) -> bool:
        """尝试用本地缓存的 Cookie 恢复登录，成功返回 True"""
        if not os.path.exists(COOKIE_CACHE):
            logger.info("无本地 Cookie 缓存，走完整登录")
            return False
        try:
            with open(COOKIE_CACHE, encoding="utf-8") as f:
                cookies = json.load(f)
        except Exception as e:
            logger.warning(f"读取 Cookie 缓存失败: {e}")
            return False
        if not cookies:
            return False

        logger.info(f"发现本地 Cookie 缓存 ({len(cookies)} 条)，验证中...")
        for ck in cookies:
            self.session.cookies.set(ck["name"], ck["value"], domain="linux.do")
        try:
            resp = self.get_with_cf_fallback(
                "https://linux.do/session/current.json", timeout=30
            )
            current_user = resp.json().get("current_user") if resp.status_code == 200 else None
            if current_user:
                self.username = current_user.get("username")
                logger.info(f"本地 Cookie 有效 (当前用户: {self.username})，跳过登录")
                dp_cookies = [
                    {"name": ck["name"], "value": ck["value"], "domain": ".linux.do", "path": "/"}
                    for ck in cookies
                ]
                self.page.set.cookies(dp_cookies)
                self.page.get(HOME_URL)
                time.sleep(3)
                return True
        except Exception as e:
            logger.warning(f"本地 Cookie 验证异常: {e}")
        logger.info("本地 Cookie 已失效，走完整登录")
        return False

    def save_cookies(self):
        """登录成功后把 Cookie 缓存到本地，供下次运行复用"""
        try:
            cookies = [
                {"name": c.name, "value": c.value, "domain": c.domain or "linux.do", "path": c.path or "/"}
                for c in self.session.cookies.jar  # 直接迭代 Cookies 得到的是名字字符串，要走 jar
            ]
            with open(COOKIE_CACHE, "w", encoding="utf-8") as f:
                json.dump(cookies, f, ensure_ascii=False, indent=2)
            logger.info(f"Cookie 已缓存到 {COOKIE_CACHE} ({len(cookies)} 条)")
        except Exception as e:
            logger.warning(f"Cookie 缓存写入失败: {e}")

    def login(self):
        logger.info("开始账号密码登录")
        # Step 1: Get CSRF Token
        logger.info("获取 CSRF token...")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": LOGIN_URL,
        }
        resp_csrf = self.get_with_cf_fallback(CSRF_URL, headers=headers)
        if resp_csrf.status_code != 200:
            logger.error(f"获取 CSRF token 失败: {resp_csrf.status_code}")
            return False        
        csrf_data = resp_csrf.json()
        csrf_token = csrf_data.get("csrf")
        logger.info(f"CSRF Token obtained: {csrf_token[:10]}...")

        # Step 2: 通过人机验证 (hCaptcha)，否则登录接口一律返回 403 invalid_access
        captcha_token, captcha_ua = self.solve_hcaptcha()
        if not captcha_token:
            return False
        logger.info("提交人机验证 token...")
        if captcha_ua:  # 提交时用 YesCaptcha 返回的 userAgent，与 token 生成环境一致
            headers["User-Agent"] = captcha_ua
        headers.update({"X-CSRF-Token": csrf_token})
        resp_verify = self.session.post(
            CAPTCHA_VERIFY_URL,
            data={"token": captcha_token},
            headers=headers,
            impersonate=self._impersonate,
        )
        if resp_verify.status_code != 200:
            logger.error(f"人机验证提交失败，状态码: {resp_verify.status_code}")
            logger.error(resp_verify.text)
            return False
        logger.info("人机验证通过!")

        # Step 3: Login
        logger.info("正在登录...")
        headers.update(
            {
                "X-CSRF-Token": csrf_token,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": "https://linux.do",
            }
        )

        data = {
            "login": USERNAME,
            "password": PASSWORD,
            "second_factor_method": "1",
            "timezone": "Asia/Shanghai",
        }

        try:
            resp_login = self.session.post(
                SESSION_URL, data=data, impersonate=self._impersonate, headers=headers
            )

            if resp_login.status_code == 200:
                response_json = resp_login.json()
                if response_json.get("error"):
                    logger.error(f"登录失败: {response_json.get('error')}")
                    return False
                logger.info("登录成功!")
            else:
                logger.error(f"登录失败，状态码: {resp_login.status_code}")
                logger.error(resp_login.text)
                return False
        except Exception as e:
            logger.error(f"登录请求异常: {e}")
            return False

        # Step 3: Pass cookies to DrissionPage
        logger.info("同步 Cookie 到 DrissionPage...")

        cookies_dict = self.session.cookies.get_dict()

        dp_cookies = []
        for name, value in cookies_dict.items():
            dp_cookies.append(
                {
                    "name": name,
                    "value": value,
                    "domain": ".linux.do",
                    "path": "/",
                }
            )

        self.page.set.cookies(dp_cookies)

        logger.info("Cookie 设置完成，导航至 linux.do...")
        self.page.get(HOME_URL)

        time.sleep(5)

        # 登录接口 200 且无 error 即已登录成功；浏览器侧验证仅作参考，
        # 因为无头浏览器可能被 CF 挑战页拦截，不代表 Cookie 无效
        try:
            resp_check = self.get_with_cf_fallback("https://linux.do/session/current.json")
            current_user = resp_check.json().get("current_user") if resp_check.status_code == 200 else None
            if current_user:
                self.username = current_user.get("username")
                logger.info(f"API 验证登录成功，当前用户: {self.username}")
            else:
                logger.warning(f"API 验证未返回 current_user (状态码 {resp_check.status_code})")
        except Exception as e:
            logger.warning(f"API 验证异常: {e}")

        page_title = self.page.title or ""
        if "Just a moment" in page_title:
            logger.warning("浏览器侧被 CF 挑战页拦截（不影响已登录会话）")
            return True
        try:
            user_ele = self.page.ele("@id=current-user")
        except Exception as e:
            logger.warning(f"浏览器侧登录验证异常: {str(e)}")
            return True
        if not user_ele:
            # Fallback check for avatar
            if "avatar" in self.page.html:
                logger.info("浏览器侧登录验证成功 (通过 avatar)")
                return True
            logger.warning("浏览器侧未找到 current-user（以 API 验证结果为准）")
            return True
        else:
            logger.info("登录验证成功")
            return True

    def _get_csrf(self):
        """懒加载 CSRF token，供点赞等写操作使用"""
        if not self._csrf_token:
            r = self.get_with_cf_fallback(CSRF_URL, headers={"X-Requested-With": "XMLHttpRequest"})
            self._csrf_token = r.json().get("csrf") if r.status_code == 200 else None
        return self._csrf_token

    def like_post(self, post_id, topic_url):
        """给帖子点 heart 回应（toggle 接口，调用前需确认未点过赞）"""
        csrf = self._get_csrf()
        if not csrf:
            logger.warning("获取 CSRF token 失败，跳过点赞")
            return False
        headers = {
            "X-CSRF-Token": csrf,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "Referer": topic_url,
        }
        url = f"https://linux.do/discourse-reactions/posts/{post_id}/custom-reactions/heart/toggle.json"
        r = self.session.put(url, headers=headers, impersonate=self._impersonate, timeout=30)
        logger.info(f"点赞帖子 {post_id}: {r.status_code}")
        return r.status_code == 200

    def _fetch_summary(self):
        """拉取用户统计，返回 (trust_level, user_summary)，失败返回 (None, None)"""
        if not self.username:
            return None, None
        resp = self.get_with_cf_fallback(f"https://linux.do/u/{self.username}/summary.json")
        if resp.status_code != 200:
            return None, None
        data = resp.json()
        summary = data.get("user_summary")
        trust_level = None
        for u in data.get("users", []):
            if u.get("username") == self.username:
                trust_level = u.get("trust_level")
                break
        return trust_level, summary

    def api_browse(self):
        """无头浏览器被 CF 拦截时，改用已登录会话直接读话题"""
        logger.info("切换到 API 方式浏览话题")
        try:
            resp = self.get_with_cf_fallback("https://linux.do/latest.json?no_definitions=true&per_page=30")
            topics = resp.json().get("topic_list", {}).get("topics", []) if resp.status_code == 200 else []
            if not topics:
                logger.error("API 获取话题列表失败")
                return False

            # 点赞按升级要求缺口来：1→2 级需要送出赞累计 1 个，够了就不再点
            max_likes = 0
            trust_level, summary = self._fetch_summary()
            if trust_level == 1 and summary is not None:
                max_likes = max(0, 1 - int(summary.get("likes_given", 0)))
            logger.info(f"本次计划点赞: {max_likes} 个")

            picked = random.sample(topics, min(10, len(topics)))
            like_count = 0
            for t in picked:
                tid = t.get("id")
                title = (t.get("title") or "")[:40]
                try:
                    r = self.get_with_cf_fallback(f"https://linux.do/t/{tid}.json?track_visit=true")
                    logger.info(f"API 阅读: {title} ({r.status_code})")
                    # toggle 接口对已赞帖子会变成取消赞，先检查 current_user_reaction
                    if r.status_code == 200 and like_count < max_likes:
                        posts = r.json().get("post_stream", {}).get("posts", [])
                        if posts and not posts[0].get("current_user_reaction"):
                            if self.like_post(posts[0].get("id"), f"https://linux.do/t/{tid}"):
                                like_count += 1
                except Exception as e:
                    logger.warning(f"API 阅读话题 {tid} 失败: {e}")
                time.sleep(random.uniform(2, 4))
            logger.info("完成 API 浏览任务")
            return True
        except Exception as e:
            logger.error(f"API 浏览异常: {e}")
            return False

    def click_topic(self):
        if "Just a moment" in (self.page.title or ""):
            logger.warning("浏览器被 CF 挑战页拦截，无法浏览")
            return False
        try:
            topic_list = self.page.ele("@id=list-area").eles(".:title")
        except Exception as e:
            logger.warning(f"浏览器获取话题列表失败: {str(e)}")
            return False
        if not topic_list:
            logger.error("未找到主题帖")
            return False
        logger.info(f"发现 {len(topic_list)} 个主题帖，随机选择10个")
        for topic in random.sample(topic_list, 10):
            self.click_one_topic(topic.attr("href"))
        return True

    @retry_decorator()
    def click_one_topic(self, topic_url):
        new_page = self.browser.new_tab()
        try:
            new_page.get(topic_url)
            if random.random() < 0.3:  # 0.3 * 30 = 9
                self.click_like(new_page)
            self.browse_post(new_page)
        finally:
            try:
                new_page.close()
            except Exception:
                pass

    def browse_post(self, page):
        prev_url = None
        # 开始自动滚动，最多滚动10次
        for _ in range(10):
            # 随机滚动一段距离
            scroll_distance = random.randint(550, 650)  # 随机滚动 550-650 像素
            logger.info(f"向下滚动 {scroll_distance} 像素...")
            page.run_js(f"window.scrollBy(0, {scroll_distance})")
            logger.info(f"已加载页面: {page.url}")

            if random.random() < 0.03:  # 33 * 4 = 132
                logger.success("随机退出浏览")
                break

            # 检查是否到达页面底部
            at_bottom = page.run_js(
                "window.scrollY + window.innerHeight >= document.body.scrollHeight"
            )
            current_url = page.url
            if current_url != prev_url:
                prev_url = current_url
            elif at_bottom and prev_url == current_url:
                logger.success("已到达页面底部，退出浏览")
                break

            # 动态随机等待
            wait_time = random.uniform(2, 4)  # 随机等待 2-4 秒
            logger.info(f"等待 {wait_time:.2f} 秒...")
            time.sleep(wait_time)

    def run(self):
        try:
            # 优先使用手动 Cookie 登录，其次本地缓存，最后账号密码
            if COOKIES:
                login_res = self.login_with_cookies(COOKIES)
                if not login_res:
                    logger.warning("Cookie 登录失败，尝试账号密码登录...")
                    login_res = self.login()
                    if login_res:
                        self.save_cookies()
            else:
                login_res = self.try_cached_login()
                if not login_res:
                    login_res = self.login()
                    if login_res:
                        self.save_cookies()
            if not login_res:
                logger.error("登录验证失败，程序终止")
                return

            if BROWSE_ENABLED:
                click_topic_res = self.click_topic()  # 点击主题
                if not click_topic_res:
                    logger.warning("浏览器浏览失败，尝试 API 浏览兜底...")
                    if not self.api_browse():
                        logger.error("浏览任务失败（浏览器与 API 均未成功）")
                else:
                    logger.info("完成浏览任务")
            self.print_user_summary()  # 打印用户统计
            self.send_notifications(BROWSE_ENABLED)  # 发送通知
        finally:
            try:
                self.page.close()
            except Exception:
                pass
            try:
                self.browser.quit()
            except Exception:
                pass

    def click_like(self, page):
        try:
            # 专门查找未点赞的按钮
            like_button = page.ele(".discourse-reactions-reaction-button")
            if like_button:
                logger.info("找到未点赞的帖子，准备点赞")
                like_button.click()
                logger.info("点赞成功")
                time.sleep(random.uniform(1, 2))
            else:
                logger.info("帖子可能已经点过赞了")
        except Exception as e:
            logger.error(f"点赞失败: {str(e)}")

    def print_user_summary(self):
        """打印用户统计与升级进度，替代已改版的 Connect Info"""
        logger.info("获取用户统计")
        trust_level, summary = self._fetch_summary()
        if not summary:
            logger.warning("用户统计获取失败")
            return

        # 升级要求来自官方说明帖: https://linux.do/t/topic/2460
        # 注意 2→3 级按"过去100天"窗口统计，summary 的累计值仅供参考
        time_read = summary.get("time_read", 0)
        h, m = divmod(int(time_read) // 60, 60)
        read_minutes = int(time_read) // 60
        if trust_level == 0:
            requirements = [
                ["进入话题", summary.get("topics_entered", 0), 5],
                ["已读帖子", summary.get("posts_read_count", 0), 30],
                ["阅读时间(分)", read_minutes, 10],
            ]
        elif trust_level == 1:
            requirements = [
                ["访问天数", summary.get("days_visited", 0), 15],
                ["送出赞", summary.get("likes_given", 0), 1],
                ["收到赞", summary.get("likes_received", 0), 1],
                ["回复话题", summary.get("post_count", 0), 3],  # 近似值：summary 无"回复过的话题数"
                ["浏览话题", summary.get("topics_entered", 0), 20],
                ["已读帖子", summary.get("posts_read_count", 0), 100],
                ["阅读时间(分)", read_minutes, 60],
            ]
        else:
            requirements = [
                ["访问天数", summary.get("days_visited", 0), "-"],
                ["浏览话题", summary.get("topics_entered", 0), "-"],
                ["已读帖子", summary.get("posts_read_count", 0), "-"],
                ["阅读时间(分)", read_minutes, "-"],
                ["送出赞", summary.get("likes_given", 0), "-"],
                ["收到赞", summary.get("likes_received", 0), "-"],
                ["发布话题", summary.get("topic_count", 0), "-"],
                ["发布回复", summary.get("post_count", 0), "-"],
            ]

        info = []
        for name, current, required in requirements:
            if required == "-":
                info.append([name, current, "-"])
            else:
                mark = "✅" if current >= required else ""
                info.append([name, current, f"{required}{mark}"])
        info.insert(0, ["信任级别", trust_level, "-"])
        logger.info("--------------用户统计-----------------")
        logger.info("\n" + tabulate(info, headers=["项目", "当前", "要求"], tablefmt="pretty"))
        if isinstance(trust_level, int) and trust_level >= 2:
            logger.info("提示: 2→3 级按过去100天窗口统计，准确进度需在 connect.linux.do 查看")

    def send_notifications(self, browse_enabled):
        """发送签到通知"""
        status_msg = f"✅每日登录成功: {self.username or USERNAME}"
        if browse_enabled:
            status_msg += " + 浏览任务完成"
        
        # 使用通知管理器发送所有通知
        self.notifier.send_all("LINUX DO", status_msg)


if __name__ == "__main__":
    if not COOKIES and (not USERNAME or not PASSWORD):
        print("请设置 LINUXDO_COOKIES（Cookie 登录），或同时设置 USERNAME 和 PASSWORD（账号密码登录）")
        exit(1)
    browser = LinuxDoBrowser()
    browser.run()
