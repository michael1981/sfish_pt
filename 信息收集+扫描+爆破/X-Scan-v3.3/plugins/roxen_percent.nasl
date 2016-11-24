#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10479);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2000-0671");
 script_bugtraq_id(1510);
 script_xref(name:"OSVDB", value:"378");

 script_name(english:"Roxen Web Server /%00/ Encoded Request Forced Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"Requesting a URL with '/%00/' appended to it makes some Roxen servers 
dump the listing of the page directory, thus showing potentially 
sensitive files.

An attacker may also use this flaw to view the source code of RXML
files, Pike scripts or CGIs.

Under some circumstances, information protected by .htaccess files might
be revealed." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Roxen." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Make a request like http://www.example.com/%00/");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
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

r = http_send_recv3(port: port, method: "GET", item: "/%00/");
seek = "Directory listing of";
data = r[0] + r[1] + '\r\n' + r[2];
if (seek >< data) security_warning(port);
