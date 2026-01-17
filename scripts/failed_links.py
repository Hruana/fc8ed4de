import re
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from loguru import logger
from typing import List, Set
from tqdm import tqdm


def filter_link(link: str) -> bool:
    """
    过滤掉不需要检查的链接
    :param link:
    :return:
    """
    allow_list = [
        'https://ghfast.top/https://raw.githubusercontent.com',
        'https://github.com/felixonmars/dnsmasq-china-list/blob/master/ns-whitelist.txt',
        'https://github.com/MetaCubeX/mihomo/blob/Meta/docs/config.yaml'
    ]
    for allow in allow_list:
        if allow in link:
            return True
            
    # 关键词过滤
    allow_keys = ['/generate_204', '/dns-query', '127.0.0.1', 'localhost']
    for allow in allow_keys:
        if allow in link:
            return True
            
    return False


def extract_links_from_parent_dir() -> List[str]:
    """
    提取父目录下所有文件中的链接
    :return:
    """
    # 获取当前脚本所在目录的父目录
    current_file = Path(__file__).resolve()
    parent_dir = current_file.parent.parent
    
    links: List[str] = []
    
    # 定义需要排除的目录和文件扩展名
    exclude_dirs = {'.git', '.venv', 'venv', '__pycache__', '.idea', 'node_modules', 'dist', 'build'}
    exclude_exts = {'.pyc', '.exe', '.dll', '.so', '.dylib', '.bin', '.png', '.jpg', '.jpeg', '.gif', '.ico'}

    for file_path in parent_dir.rglob('*'):
        # 排除目录
        if file_path.is_dir():
            continue
            
        # 检查路径中是否包含排除的目录名
        if any(part in exclude_dirs for part in file_path.parts):
            continue
            
        # 排除特定扩展名
        if file_path.suffix.lower() in exclude_exts:
            continue

        try:
            # 尝试读取文件，忽略编码错误
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            # 改进的正则：匹配 http/https 开头，直到遇到空白字符、引号、括号或常见标点
            file_links = re.findall(r'https?://[a-zA-Z0-9\.\-_/~:?#\[\]@!$&*+,;=%]+', content)
            links.extend(file_links)
        except Exception as e:
            logger.warning(f'无法读取文件: {file_path}, 错误: {e}')

    # 清理和过滤链接
    cleaned_links = set()
    for link in links:
        # 去除可能的尾随标点
        link = link.rstrip('.,;)\'"')
        if not filter_link(link):
            cleaned_links.add(link)

    logger.info(f'提取到 {len(cleaned_links)} 个需检查的链接')
    return list(cleaned_links)


def check_single_link(link: str) -> None:
    """
    检查单个链接
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        }
        # 增加 timeout 防止卡死
        r = requests.head(link, headers=headers, allow_redirects=True, timeout=10)
        if r.status_code != 200:
            # 有些网站 head 请求返回 403/404/405 但 get 正常，可以视情况复查，这里暂按原逻辑报错
            logger.error(f'{link} is failed, status code: {r.status_code}')
    except requests.exceptions.Timeout:
        logger.error(f'{link} is failed, timeout')
    except requests.exceptions.RequestException as e:
        logger.error(f'{link} is failed, error: {e}')
    except Exception as e:
        logger.error(f'{link} is failed, unexpected error: {e}')


def check_links(links: List[str]) -> None:
    """
    并发检查链接是否可用
    :param links:
    :return:
    """
    # 使用 ThreadPoolExecutor 进行并发检查
    max_workers = min(32, len(links) + 1)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        futures = [executor.submit(check_single_link, link) for link in links]
        
        # 使用 tqdm 显示进度条，等待所有任务完成
        for _ in tqdm(as_completed(futures), total=len(links), desc="Checking links", unit="link"):
            pass


if __name__ == '__main__':
    extracted_links = extract_links_from_parent_dir()
    check_links(extracted_links)
