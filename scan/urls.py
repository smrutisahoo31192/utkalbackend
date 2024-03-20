from django.urls import path

from . import views

urlpatterns = [
    path("get-ip/", views.scan_get_ip, name="scan_get_ip"),
    path("ssl/", views.scan_ssl, name="scan_ssl"),
    path("quality/", views.scan_quality, name="scan_quality"),
    path("headers/", views.scan_headers, name="scan_headers"),
    path("dns/", views.scan_dns, name="scan_dns"),
    path("whois/", views.scan_whois, name="scan_whois"),
    path("port/", views.scan_port, name="scan_port"),
    path("trace/", views.scan_trace, name="scan_trace"),
    path("ping/", views.scan_ping, name="scan_ping"),
    path("http-security/", views.scan_http_security, name="scan_http_security"),
    path("block-lists/", views.scan_blocklists, name="scan_blocklists"),
    path("carbon/", views.scan_carbon, name="scan_carbon"),
    path("hsts/", views.scan_hsts, name="scan_hsts"),
    path("dns-server/", views.scan_dns_server, name="scan_dns_server"),
    path("txt-records/", views.scan_txt_records, name="scan_txt_records"),
    path("threats/", views.scan_threats, name="scan_threats"),
]
