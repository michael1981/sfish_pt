#
# (C) Tenable Network Security, Inc.
#

# Date:  Fri, 7 Dec 2001 14:23:10 +0100
# From: "Sebastien EXT-MICHAUD" <Sebastien.EXT-MICHAUD@atofina.com>
# Subject: Lotus Domino Web server vulnerability
# To: bugtraq@securityfocus.com



include("compat.inc");

if (description)
{
  script_id(11718);
  script_version("$Revision: 1.9 $");
  script_cve_id("CVE-2001-0954");
  script_bugtraq_id(3656);
  script_xref(name:"OSVDB", value:"2000");

  script_name(english:"Lotus Domino /./ Request Database Locking DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It might be possible to lock out some Lotus Domino databases by 
requesting them through the web interface with a special request
containing a '/./' string in the URL path.

This attack is only efficient on databases that are not used by
the server.

*** Note that no real attack was performed, 
*** so this may be a false positive" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino 5.0.9 or later, as this reportedly fixes
the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
  script_summary(english:"Locks out Lotus database with /./ request");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"Denial of Service");
  script_dependencie("http_version.nasl", "find_service1.nasl", "http_login.nasl", "httpver.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/domino");
  exit(0);

}

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


b = get_http_banner(port: port);
if(egrep(pattern: "^Server: Lotus-Domino/(Release-)?(5\.0\.[0-8][^0-9])", string:b))
  security_warning(port);
