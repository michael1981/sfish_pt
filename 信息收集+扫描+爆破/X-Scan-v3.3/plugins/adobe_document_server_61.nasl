#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21220);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-1627", "CVE-2006-1785", "CVE-2006-1786", "CVE-2006-1787", "CVE-2006-1788");
  script_bugtraq_id(17500);
  script_xref(name:"OSVDB", value:"24587");
  script_xref(name:"OSVDB", value:"24588");
  script_xref(name:"OSVDB", value:"24589");
  script_xref(name:"OSVDB", value:"24590");
  script_xref(name:"OSVDB", value:"24591");
  script_xref(name:"OSVDB", value:"24592");

  script_name(english:"Adobe Document Server for Reader Extensions < 6.1 Multiple Vulnerabilities");
  script_summary(english:"Tries to exploit an XSS flaw in Adobe Document Server for Reader Extensions");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Adobe Document Server, a server that
dynamically creates and manipulates PDF documents as well as graphic
images. 

The version of Adobe Document Server installed on the remote host
includes the Adobe Document Server for Reader Extensions component,
which itself is affected by several issues :

  - Missing Access Controls
    An authenticated user can gain access to functionality to which 
    they should not have access by manipulating the 'actionID' and
    'pageID' parameters.

  - Cross-Site Scripting Flaws
    The application fails to sanitize input to several parameters
    before using it to generate dynamic web content.

  - Information Disclosure
    The application exposes a user's session id in the Referer
    header, which can lead to a loss of confidentiality. Also,
    the application returns different error messages during
    unsuccessful authentication attempts, which can be used to
    enumerate users." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-68/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/techdocs/322699.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/techdocs/331915.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/techdocs/331917.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Document Server for Reader Extensions 6.1 / LiveCycle
Reader Extensions 7.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8019);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:8019);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '")</script>';

# Try to exploit one of the XSS flaws.
r = http_send_recv3(method:"GET", port: port,
  item:string("/altercast/AlterCast?", "op=", urlencode(str:xss)));
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if we see our XSS.
if ("/altercast/images/AdobeLogo.gif" >< res && string("<h2>", xss) >< res)
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
