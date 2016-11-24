#
# This script is (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(17210);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2005-0516");
 script_bugtraq_id(12637, 12638);
 script_xref(name:"OSVDB", value:"14126");

 script_name(english:"TWiki ImageGalleryPlugin Shell Command Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
arbitrary command execution flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote installation of TWiki is
vulnerable to a shell command injection issue in the 
ImageGalleryPlugin component.

In addition, the wording of a 'robustness' patch released by the vendor
indicates this version may be vulnerable to other input validation 
issues. However, the patch may contain proactive security enhancements
and not fix specific vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110918725225288&w=2" );
 script_set_attribute(attribute:"solution", value:
"Apply the TWiki robustness patch referenced in the advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of TWiki");
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("twiki_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (egrep(pattern:"(1999|200[0-4])", string:ver)) 
    security_hole(port);
}
