from bs4 import BeautifulSoup
import urllib.request

html = urllib.request.urlopen(
    'https://vietnamnet.vn/').read()

soup = BeautifulSoup(html, "html.parser").encode("utf-8")

print(soup.title.name)
# expected: <title>Báo VietNamNet - Tin tức online, tin nhanh Việt Nam và thế giới<title>
