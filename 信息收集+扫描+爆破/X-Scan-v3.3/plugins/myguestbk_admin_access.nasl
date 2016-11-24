#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Date: Wed, 27 Mar 2002 18:07:27 +0300
# From: Over_G <overg@mail.ru>
# Subject: Vulnerability in my guest book 
# To: vuln@security.nnov.ru, bugtraq@securityfocus.com
#
# This script check for a vulnerability which is used by at least ONE 
# person in the world. Seriously, I wonder if it's really worth writing
# such scripts....



include("compat.inc");

if(description)
{
 script_id(11489);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(7213);
 script_xref(name:"OSVDB", value:"4625");
 script_xref(name:"OSVDB", value:"54591");

 script_name(english:"My Guest Book (myGuestBk) Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
multiple applications." );
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting myGuestBook.

This installation comes with an administrative file in 
'myguestBk/admin/index.asp' which lets any user delete old entries.

In addition to this, this CGI is vulnerable to a cross-site-scripting
attack." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/390" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of admin/index.asp");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("http.inc");
include("global_settings.inc");
include("misc_func.inc");
port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0);

dirs = make_list(cgi_dirs(), "/myguestbk");

foreach dir (dirs)
{
  res = http_send_recv3(method:"GET", item:string(dir, "/admin/index.asp"), port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if ("Delete this entry" >< res[2])
  {
    security_hole(port);
    set_kb_item(name:'www/'+port+'/XXX', value:TRUE);
    exit(0);
  }
}
