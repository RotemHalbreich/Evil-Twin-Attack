DNSMASK = '''interface={}
dhcp-range=192.168.1.2,192.168.1.250,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
'''
HOSTAPD = '''interface={}
ssid={}
channel={}
driver=nl80211
'''
APACHE_CONF = '''<Directory "/var/www/html">
RewriteEngine On
RewriteBase /
RewriteCond %{HTTP_HOST} ^www\.(.*)$ [NC]
RewriteRule ^(.*)$ http://%1/$1 [R=301,L]

RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ / [L,QSA]
</Directory>
'''
file_name_apache_conf = '/etc/apache2/sites-enabled/000-default.conf'
file_name_dns_masq = 'dnsmasq.conf'
file_name_hostapd = 'hostapd.conf'
path_to_apache_http = '/var/www/html/'

