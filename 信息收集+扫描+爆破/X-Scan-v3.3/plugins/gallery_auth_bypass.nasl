#
# (C) Tenable Network Security, Inc.
#
#


include("compat.inc");

if(description)
{
 script_id(12278);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2004-0522");
 script_bugtraq_id(10451);
 script_xref(name:"OSVDB", value:"6524");
 script_xref(name:"Secunia", value:"11752");
 script_xref(name:"Secunia", value:"11758");
 script_xref(name:"Secunia", value:"11873");

 script_name(english:"Gallery init.php Authentication Bypass");
 script_summary(english:"Attempts to bypass authentication in Gallery");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a PHP application that is affected by an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Gallery web-based photo album.

There is a flaw in this version which may allow an attacker to bypass
the authentication mechanism of this software by making requests including
the options GALLERY_EMBEDDED_INSIDE and GALLERY_EMBEDDED_INSIDE_TYPE.
An attacker who can bypass authentication will obtain Galelry
administrator privileges." );
 script_set_attribute(attribute:"see_also", value:"http://gallery.menalto.com/node/123" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gallery 1.4.3p2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);


function check(url)
{
  local_var r, req;
  r = http_send_recv3(method:"GET", item:string(url,"/index.php"), port:port);
  if ( isnull(r)) exit(0);
  if(egrep(pattern:'<span class="admin"><a id="popuplink_1".*\\[login\\]', string:r)
  )
  {
    r = http_send_recv3(method:"GET", item:string(url, "/index.php?GALLERY_EMBEDDED_INSIDE=y"), port:port);
    if (isnull(r)) exit(0);
    if(egrep(pattern:'<span class="admin"><a id="popuplink_1".*\\[login\\]', string:r) == 0 )
      security_hole(port);
    exit(0);
  }
}

check(url:"");
foreach dir (cgi_dirs())
{
 check(url:dir);
}
