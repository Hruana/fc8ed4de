import re
import requests
import os
from loguru import logger


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

    logger.info(f'提取到 {len(links)} 个链接')
    return links


def check_links(links):
    for link in links:
        if 'generate_204' in link or 'dns-query' in link or '127.0.0.1' in link:
            continue
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            }
            # 去除链接中的%22
            link = link.strip().strip('"').strip("'").strip("',") # 万无一失！
            r = requests.head(link, headers=headers, allow_redirects=True)
            if r.status_code != 200:
                logger.error(f'{link} is failed, status code: {r.status_code}')
            # else:
            #     logger.info(f'{link} {r.status_code}')
        except Exception as e:
            logger.error(f'{link} is failed, {e}')


if __name__ == '__main__':
    links = extract_links_from_parent_dir()
    check_links(links)
