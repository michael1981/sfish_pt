#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/7/2009)
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(25446);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2007-0563","CVE-2007-0564");
 script_bugtraq_id(22184);
 script_xref(name:"OSVDB", value:"32959");
 script_xref(name:"OSVDB", value:"32960");
 script_xref(name:"OSVDB", value:"32961");

 script_name(english:"Symantec Web Security (SWS) Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Symantec Web Security on the
remote host is vulnerable to denial of service and cross-site
scripting attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade at least to version 3.0.1.85." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for SWS flaws");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 David Maciejak");
 
 script_family(english:"CGI abuses");
 script_dependencie("symantec_ws_detection.nasl");
 script_require_ports("Services/www", 8002);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/www");
if ( ! port ) port = 8002;
if(!get_port_state(port)) exit(0);

version=get_kb_item(string("www/", port, "/SWS"));
if (version) {
	if (ereg(pattern:"^(2\.|3\.0\.(0|1\.([0-9]|[1-7][0-9]|8[0-4])$))", string:version))
	{
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
}
