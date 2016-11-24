#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Debian security team
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/2/2009)


include("compat.inc");

if(description)
{
 script_id(15710);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2004-0983");
 script_bugtraq_id(11618);
 script_xref(name:"OSVDB", value:"11534");

 script_name(english:"Ruby cgi.rb Malformed HTTP Request CPU Utilization DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by a denial-of-service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'cgi.rb' CGI is installed. Some versions is vulnerable to
remote denial of service.

By sending a specially crafted HTTP POST request, a malicious user can
force the remote host to consume a large amount of CPU resources.

*** Warning : Nessus solely relied on the presence of this 
*** CGI, it did not determine if you specific version is 
*** vulnerable to that problem." );
 script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2004-635.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2004/dsa-586" );
 script_set_attribute(attribute:"see_also", value:"http://www.gentoo.org/security/en/glsa/glsa-200612-21.xml" );
 script_set_attribute(attribute:"see_also", value:"http://www.mandrakesoft.com/security/advisories?name=MDKSA-2004:128" );
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/linux/security/advisories/2005_04_sr.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-394-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Ruby 1.8.1 or later" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for the presence of cgi.rb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"cgi.rb", port:port);
if(res)security_warning(port);
