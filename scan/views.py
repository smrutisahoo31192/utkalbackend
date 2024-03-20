from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
import requests
from datetime import datetime

# Create your views here.

URLS = [
    {"get_ip": "https://web-check.xyz/api/get-ip"},
    {"ssl": "https://web-check.xyz/api/ssl"},
    {"headers": "https://web-check.xyz/api/headers"},
    {"dns": "https://web-check.xyz/api/dns"},
    {"whois": "https://web-check.xyz/api/whois"},
    {"port": "https://web-check.xyz/api/port"},
    {"trace": "https://web-check.xyz/api/trace"},
    {"ping": "https://web-check.xyz/api/ping"},
    {"speed": "https://web-check.xyz/api/speed"},
    {"uptime": "https://web-check.xyz/api/uptime"},
    {"blacklist": "https://web-check.xyz/api/blacklist"},
    {"links": "https://web-check.xyz/api/links"},
    {"screenshot": "https://web-check.xyz/api/screenshot"},
    {"http_security": "https://web-check.xyz/api/http-security"},
    {
        "quality": "https://web-check.xyz/api/quality",
    },
    {"blocklist": "https://web-check.xyz/api/block-lists"},
    {"carbon": "https://web-check.xyz/api/carbon"},
    {"hsts": "https://web-check.xyz/api/hsts"},
    {"dnsserver": "https://web-check.xyz/api/dns-server"},
    {"txtrecords": "https://web-check.xyz/api/txt-records"},
    {"threats": "https://web-check.xyz/api/threats"},
]


def scan_dns_server(request):
    # call the api 'get_ip' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[18]["dnsserver"] + "?url=" + url

    response_data = requests.get(request_url)
    print(response_data.json())

    response_dict = format_dns_server(response_data.json())

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_hsts(request):
    # call the api 'get_ip' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[17]["hsts"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_hsts(response_data.json())

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_carbon(request):
    # call the api 'get_ip' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[16]["carbon"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_carbon_data(response_data.json())

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_get_ip(request):
    # call the api 'get_ip' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[0]["get_ip"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_txt_records(request):
    # call the api 'get_ip' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[19]["txtrecords"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_threats(request):
    # call the api 'get_ip' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[20]["threats"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_threats(response_data.json())

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_ssl(request):
    # call the api 'ssl' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[1]["ssl"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = transform_ssl_certificate(response_data.json())

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_http_security(request):
    # call the api 'http_security' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[13]["http_security"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_quality(request):
    # call the api 'quality' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[14]["quality"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_blocklists(request):
    # call the api 'quality' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[15]["blocklist"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = transform_blocklists(response_data.json())

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_headers(request):
    # call the api 'headers' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[2]["headers"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_dns(request):
    # call the api 'dns' from URLS and return the response

    response_data = requests.get()

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[3]["dns"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_whois(request):
    # call the api 'whois' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[4]["whois"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_port(request):
    # call the api 'port' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[5]["port"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_trace(request):
    # call the api 'trace' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[6]["trace"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_ping(request):
    # call the api 'ping' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[7]["ping"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_speed(request):
    # call the api 'speed' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[8]["speed"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_uptime(request):
    # call the api 'uptime' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[9]["uptime"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_blacklist(request):
    # call the api 'blacklist' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[10]["blacklist"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_links(request):
    # call the api 'links' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[11]["links"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def scan_screenshot(request):
    # call the api 'screenshot' from URLS and return the response

    url = request.GET.get("url")

    # create the api url "https://web-check.xyz/api/get-ip?url=https://utkal.io"
    request_url = URLS[12]["screenshot"] + "?url=" + url

    response_data = requests.get(request_url)

    response_dict = format_response(response_data)

    return JsonResponse({"data": response_dict}, status=status.HTTP_200_OK)


def format_response(response_data):
    # format the response data
    # convert the response data to json format
    # return the response data

    response_dict = response_data.json()

    return response_dict


def transform_ssl_certificate(input_data):
    output_data = {
        "Subject": input_data["subject"]["CN"],
        "Issuer": input_data["issuer"]["O"],
        "Expires": datetime.strptime(
            input_data["valid_to"], "%b %d %H:%M:%S %Y %Z"
        ).strftime("%d %B %Y"),
        "Renewed": datetime.strptime(
            input_data["valid_from"], "%b %d %H:%M:%S %Y %Z"
        ).strftime("%d %B %Y"),
        "Serial Num": input_data["serialNumber"],
        "Fingerprint": [input_data["fingerprint"], input_data["fingerprint256"]],
        "Extended Key Usage": input_data["ext_key_usage"],
    }

    return output_data


def transform_blocklists(input_data):
    transformed_dict = {}
    for entry in input_data.get("blocklists", []):
        server = entry.get("server")
        is_blocked = True if entry.get("isBlocked") == False else False
        transformed_dict[server] = is_blocked
    return transformed_dict


def format_carbon_data(input_data):
    statistics = input_data.get("statistics", {})

    initial_size_bytes = statistics.get("adjustedBytes", 0)
    co2_initial_load_grams = statistics.get("co2", {}).get("grid", {}).get("grams", 0)
    energy_usage_kwgh = statistics.get("energy", 0)
    co2_emitted_grams = statistics.get("co2", {}).get("renewable", {}).get("grams", 0)

    result = {
        "HTML Initial Size": f"{initial_size_bytes:.2f} bytes",
        "CO2 for Initial Load": f"{co2_initial_load_grams:.2f} grams",
        "Energy Usage for Load": f"{energy_usage_kwgh:.4f} KWg",
        "CO2 Emitted": f"{co2_emitted_grams:.2f} grams",
    }

    return result


def format_hsts(input_data):
    compatible = input_data.get("compatible", False)

    result = {"HSTS Enabled?": compatible}

    return result


def format_dns_server(input_data):
    domain = input_data.get("domain", "")
    dns_list = input_data.get("dns", [])

    result = {"IP Address": None, "DoH Support": False}

    for dns_entry in dns_list:
        ip_address = dns_entry.get("address", "")
        doh_support = dns_entry.get("dohDirectSupports", False)

        if ip_address:
            result["IP Address"] = ip_address
            result["DoH Support"] = doh_support

    return result


def format_threats(input_data):
    print(input_data)
    print(input_data.get("phishTank", {}).get("url0", {}).get("in_database", "false"))
    result = {
        "Google Safe Browsing": True
        if input_data.get("safeBrowsing", {}).get("unsafe", False) == False
        else False,
        "Phishing Status": True
        if input_data.get("phishTank", {}).get("url0", {}).get("in_database", "false")
        == "false"
        else False,
        "Malware Status": input_data.get("urlHaus", {}).get("query_status", "")
        == "no_results",
    }
    return result
