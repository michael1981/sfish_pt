#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: ned <nd@felinemenace.org>
#
#  This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title, changed family (1/22/2009)


include("compat.inc");

if(description)
{
 script_id(15397);
 script_cve_id("CVE-2004-2027");
 script_bugtraq_id(10311);
 script_xref(name:"OSVDB", value:"6075");
 script_version ("$Revision: 1.11 $");
 
 script_name(english:"Icecast HTTP Basic Authorization Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote media server is vulnerable to a remote denial-of-service
attack." );
 script_set_attribute(attribute:"description", value:
"The remote server runs Icecast 2.0.0, an open source streaming audio 
server.

This version is affected by a remote denial of service.

An remote attacker could send specially crafted URL, with a long 
string passed in an Authorization header that will result in a loss
of availability for the service.

*** Nessus reports this vulnerability using only
*** information that was gathered." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5065a57" );
 script_set_attribute(attribute:"see_also", value:"http://www.gentoo.org/security/en/glsa/glsa-200405-10.xml" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-05/0378.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 2.0.1 or later, as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 
 summary["english"] = "Check icecast version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
		
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if (! banner ) exit(0);
if("icecast/" >< banner && egrep(pattern:"icecast/2\.0\.0([^0-9]|$)", string:banner))
      security_warning(port);
