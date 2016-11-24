#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23651);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-5819");
  script_bugtraq_id(21120);
  script_xref(name:"OSVDB", value:"30286");
  script_xref(name:"OSVDB", value:"30287");
  script_xref(name:"OSVDB", value:"30288");

  script_name(english:"Verity Ultraseek < 5.7 Multiple Vulnerabilities");
  script_summary(english:"Checks for Ultraseek < 5.7");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ultraseek, an enterprise web search engine. 

According to the version in its banner, an unauthenticated remote
attacker reportedly can use '/highlight/index.html' script on the
remote install of Ultraseek as a proxy to launch web attacks or even
enumerate internal addresses and ports. 

In addition, the remote software also suffers from numerous
information disclosure vulnerabilities through other scripts." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-042.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/451847/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.ultraseek.com/support/docs/RELNOTES.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ultraseek 5.7 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8765);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8765);


# Check the version in the banner.
banner = get_http_banner(port:port);
if (
  banner &&
  "Server: Ultraseek" >< banner &&
  egrep(pattern:"^Server: Ultraseek/([0-4]\.|5\.[0-6]\.)", string:banner)
) security_hole(port);
