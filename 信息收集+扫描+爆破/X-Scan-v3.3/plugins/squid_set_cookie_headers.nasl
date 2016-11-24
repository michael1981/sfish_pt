#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19237);
  script_version ("$Revision: 1.9 $");

  script_cve_id("CVE-2005-0626");
  script_bugtraq_id(12716);
  script_xref(name:"OSVDB", value:"14354");

  script_name(english:"Squid Set-Cookie Header Cross-session Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by an information disclosure
issue." );
 script_set_attribute(attribute:"description", value:
"The remote Squid caching proxy, according to its banner, is prone to
an information disclosure vulnerability.  Due to a race condition,
Set-Cookie headers may leak to other users if the requested server
employs the deprecated Netscape Set-Cookie specifications with regards
to how cacheable content is handled." );
 script_set_attribute(attribute:"see_also", value:"http://www.squid-cache.org/Versions/v2/2.5/bugs/#squid-2.5.STABLE9-setcookie" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor URL above or upgrade to
version 2.5 STABLE10 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_summary(english:"Checks for Set-Cookie headers information disclosure vulnerability in Squid");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls"); 
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/http_proxy",3128, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/http_proxy");
if (!port) {
  if (get_port_state(3128)) port = 3128;
  else port = 8080;
}

if (! get_port_state(port)) exit(0);

rq = http_mk_get_req(port: port, item: "/"); # DON'T use http_mk_proxy_request!
r = http_send_recv_req(port:port, req: rq);
if (egrep(pattern:"Squid/2\.([0-4]\.|5\.STABLE[0-9][^0-9])", string: r[1]+r[2]))
      security_warning(port);

