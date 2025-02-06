import re
import requests
from loguru import logger


def get_links():
    with open('../General.ini', 'r', encoding='utf-8') as f:
        content = f.read()
    # 匹配所有链接，也有可能是http
    links = re.findall(r'https?://[^\s]+', content)
    logger.info(f'Get {len(links)} links')
    return links


def check_links(links):
    for link in links:
        if 'generate_204' in link:
            continue
        try:
            r = requests.head(link)
            if r.status_code != 200:
                logger.error(f'{link} is failed')
            else:
                logger.info(f'{link} is ok')
        except:
            logger.error(f'{link} is failed')


if __name__ == '__main__':
    links = get_links()
    check_links(links)
