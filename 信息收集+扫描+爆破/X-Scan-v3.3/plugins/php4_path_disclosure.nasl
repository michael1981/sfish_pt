#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# based on php3_path_disclosure by Matt Moore


include("compat.inc");

if(description)
{
 script_id(11008);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2002-0249");
 script_bugtraq_id(4056);
 script_xref(name:"OSVDB", value:"827");

 script_name(english:"PHP4 for Apache on Windows php.exe Malformed Request Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"PHP4 will reveal the physical path of the webroot when asked for a 
nonexistent PHP4 file." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of PHP and Apache." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Tests for PHP4 Physical Path Disclosure Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

# Actual check starts here...
# Check makes a request for nonexistent php3 file...
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 if ( ! can_host_php(port:port) ) exit(0);

r = http_send_recv3(method: "GET", item:"/nosuchfile.php/123", port:port);
if (isnull(r)) exit(0);

buf = strcat(r[0], r[1], '\r\n', r[2]);
if ("Unable to open" >< buf) security_warning(port);

