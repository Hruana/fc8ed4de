import re
import requests
import os
from loguru import logger


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
    allow_keys = ['/generate_204', '/dns-query', '127.0.0.1']
    for allow in allow_keys:
        if allow in link:
            return True
    return False


def extract_links_from_parent_dir():
    """
    提取父目录下所有文件中的链接
    :return:
    """
    parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    links = []

    for root, _, files in os.walk(parent_dir):
        # 排除特定目录(.git)
        if '.git' in root:
            continue
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    file_links = re.findall(r'https?://[^\s]+', content)
                    links.extend(file_links)
            except Exception as e:
                logger.error(f'无法读取文件: {file_path}, 错误: {e}')

    # 去除链接中的%22
    links = [link.strip().strip('"').strip("'").strip("',") for link in links]
    # 过滤
    links = [link for link in links if not filter_link(link)]
    # 去重
    links = list(set(links))
    logger.info(f'提取到 {len(links)} 个链接')
    return links


def check_links(links):
    """
    检查链接是否可用
    :param links:
    :return:
    """
    for link in links:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            }
            r = requests.head(link, headers=headers, allow_redirects=True)
            if r.status_code != 200:
                logger.error(f'{link} is failed, status code: {r.status_code}')
            # else:
            #     logger.info(f'{link} {r.status_code}')
        except Exception as e:
            logger.error(f'{link} is failed, {e}')


if __name__ == '__main__':
    check_links(extract_links_from_parent_dir())
