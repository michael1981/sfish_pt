#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(15974);
 script_cve_id("CVE-2004-1400");
 script_bugtraq_id(11931);
 script_version("$Revision: 1.5 $");
 name["english"] = "Ocean12 ASP Calendar Administrative Access";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that fails to restrict 
administrative access to non-admin users." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ocean12 ASP Calendar, a web based
application written in ASP.

There is a flaw in the remote software which may allow anyone
execute admnistrative commands on the remote host by requesting
the page /admin/main.asp.

An attacker may exploit this flaw to deface the remote site without
any credentials." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "auth bypass test";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0,"Remote server does not support ASP.");

foreach dir (cgi_dirs()) 
{
  res = http_send_recv3(method:"GET", item:dir + "/admin/main.asp", port:port);

  if ( isnull(res)) exit(1,"Null response to main.asp request");
  if ("<title>Ocean12 ASP Calendar Manager</title>" >< res[2] &&
      '<a href="add.asp">' >< res[2] )
  {
    security_hole(port);
    exit(0);
  }
}
