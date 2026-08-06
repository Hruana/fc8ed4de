#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""链接可用性巡检：扫描项目内所有文件里的 http(s) 链接并逐个检查。

失效的链接需要人工判断替换成什么，所以本脚本只做检查和汇总，不自动改动任何文件，
也不接入 CI —— 手动运行、人工处理。

用法:
    python failed_links.py

退出码: 0 全部可用；1 存在不可用链接。
"""

import re
import sys
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from typing import List, Optional, Tuple

from tqdm import tqdm

MAX_WORKERS = 16

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
    ),
}

# HEAD 不可信、需要用 GET 复核的状态码。GitHub 系域名对 HEAD 常返 403/405，
# 直接按 HEAD 结果判定会产生大量假警报。
HEAD_UNRELIABLE = frozenset({400, 401, 403, 405, 406, 501})

# 无需检查的链接：加速镜像前缀、指向仓库页面的参考链接、本机与探测地址
SKIP_PREFIXES = (
    'https://ghfast.top/https://raw.githubusercontent.com',
    'https://github.com/felixonmars/dnsmasq-china-list/blob/master/ns-whitelist.txt',
    'https://github.com/MetaCubeX/mihomo/blob/Meta/docs/config.yaml',
)
SKIP_KEYWORDS = ('/generate_204', '/dns-query', '127.0.0.1', 'localhost')

EXCLUDE_DIRS = {'.git', '.venv', 'venv', '__pycache__', '.idea', 'node_modules', 'dist', 'build'}
EXCLUDE_EXTS = {
    '.pyc', '.exe', '.dll', '.so', '.dylib', '.bin',
    '.png', '.jpg', '.jpeg', '.gif', '.ico',
}

LINK_RE = re.compile(r'https?://[a-zA-Z0-9\.\-_/~:?#\[\]@!$&*+,;=%]+')


def should_skip(link: str) -> bool:
    """判断链接是否无需检查"""
    if any(link.startswith(prefix) or prefix in link for prefix in SKIP_PREFIXES):
        return True
    return any(keyword in link for keyword in SKIP_KEYWORDS)


def extract_links_from_parent_dir() -> List[str]:
    """
    提取父目录下所有文件中的链接
    :return: 去重、排序后的待检查链接
    """
    parent_dir = Path(__file__).resolve().parent.parent
    links: List[str] = []
    unreadable: List[str] = []

    for file_path in parent_dir.rglob('*'):
        if file_path.is_dir():
            continue
        # 只看相对项目根的路径：仓库若 checkout 在名为 build/dist/venv 的目录下，
        # 用绝对路径判断会把整个项目排除掉、静默扫到 0 个文件
        if any(part in EXCLUDE_DIRS for part in file_path.relative_to(parent_dir).parts):
            continue
        if file_path.suffix.lower() in EXCLUDE_EXTS:
            continue

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            unreadable.append(f'{file_path}: {e}')
            continue
        links.extend(LINK_RE.findall(content))

    for message in unreadable:
        print(f'警告: 无法读取文件 {message}')

    cleaned = {link.rstrip('.,;)\'"') for link in links}
    targets = sorted(link for link in cleaned if not should_skip(link))

    print(f'提取到 {len(cleaned)} 个链接，其中 {len(targets)} 个需要检查')
    return targets


def check_single_link(link: str, session: requests.Session) -> Optional[str]:
    """
    检查单个链接。先 HEAD，遇到 HEAD 不可信的状态码再用 GET 复核。
    :return: 失败原因；可用则返回 None
    """
    try:
        response = session.head(link, headers=HEADERS, allow_redirects=True, timeout=10)
        if response.status_code in HEAD_UNRELIABLE or response.status_code >= 500:
            # 只读响应头就断开，不下载正文
            with session.get(
                link, headers=HEADERS, allow_redirects=True, timeout=15, stream=True
            ) as verified:
                status = verified.status_code
        else:
            status = response.status_code

        if status != 200:
            return f'status {status}'
    except requests.exceptions.Timeout:
        return 'timeout'
    except requests.exceptions.RequestException as e:
        return f'{type(e).__name__}: {e}'
    except Exception as e:
        return f'unexpected {type(e).__name__}: {e}'

    return None


def check_links(links: List[str]) -> List[Tuple[str, str]]:
    """
    并发检查链接是否可用
    :return: [(链接, 失败原因)]
    """
    if not links:
        return []

    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=MAX_WORKERS, pool_maxsize=MAX_WORKERS)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    failures: List[Tuple[str, str]] = []
    max_workers = min(MAX_WORKERS, len(links))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_link = {executor.submit(check_single_link, link, session): link for link in links}
        # 结果统一在结束后汇总输出，避免日志把进度条冲乱
        for future in tqdm(
            as_completed(future_to_link), total=len(links), desc='Checking links', unit='link'
        ):
            link = future_to_link[future]
            reason = future.result()
            if reason:
                failures.append((link, reason))

    session.close()
    return failures


def main() -> int:
    links = extract_links_from_parent_dir()
    failures = check_links(links)

    print()
    if not failures:
        print(f'全部 {len(links)} 个链接可用。')
        return 0

    print(f'{len(failures)}/{len(links)} 个链接不可用，需人工确认替换:')
    for link, reason in sorted(failures):
        print(f'  [{reason}] {link}')
    return 1


if __name__ == '__main__':
    sys.exit(main())
