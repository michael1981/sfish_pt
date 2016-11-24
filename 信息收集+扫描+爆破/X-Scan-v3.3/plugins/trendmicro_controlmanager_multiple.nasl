#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(20401);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-1929");
  script_bugtraq_id(15865, 15866, 15867);
  script_xref(name:"OSVDB", value:"21771");
  script_xref(name:"OSVDB", value:"21772");

  script_name(english:"Trend Micro ControlManager < 3.0 SP5 Multiple Vulnerabilities");
  script_summary(english:"Checks for ControlManager version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to remote code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Trend Micro ControlManager. 

The version of ControlManager is vulnerable to a buffer overrun in CGI
programs which may allow a remote attacker to execute code in the
context of ControlManager.  This version is also vulnerable to a
denial of service (DoS) attack in the way it handles ISAPI requests. 

Note that ControlManager under Windows runs with SYSTEM privileges,
which means an attacker can gain complete control of the affected
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/download/product.asp?productid=7" );
 script_set_attribute(attribute:"solution", value:
"Apply Trend Micro Service Pack 5 for ControlManager 3.0." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

w = http_send_recv3(method:"GET", item:"/ControlManager/cgi-bin/dm_autologin_cgi.exe?-V", port:port);
if (isnull(w)) exit(1, "the web server did not answer");

res = strcat(w[0], w[1], '\r\n', w[2]);

# Service Pack 5 update the version 3.00.4208
res = strstr (res, "TMI-DM version:");
if (!res)
  exit (0);

if (egrep (pattern:"TMI-DM version: [0-2]\.", string:res))
{
 security_hole(port);
 exit (0);
}

if (egrep (pattern:"TMI-DM version: 3.0, build: .00.([0-9]+)", string:res))
{
 build = ereg_replace (pattern:"TMI-DM version: 3.0, build: .00.([0-9]+).*", string:res, replace:"\1");
 build = int (build);

 if (build < 4208)
   security_hole(port);
}
