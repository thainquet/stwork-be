from bs4 import BeautifulSoup
import urllib.request
html = urllib.request.urlopen('https://vietnamnet.vn/').read()

soup = BeautifulSoup(html, "html.parser")
print(soup.title)
