#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/16/009)


include("compat.inc");

if(description)
{
 script_id(10099);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-1999-1053");
 script_bugtraq_id(776);
 script_xref(name:"OSVDB", value:"84");

 script_name(english:"Matt Wright guestbook.pl Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The 'guestbook.pl' is installed. This CGI has a well known security flaw
that lets anyone execute arbitrary commands with the privileges of the 
HTTP daemon (root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/guestbook.pl");
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2009 Mathieu Perrin");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 
 exit(0);
}	  
  
#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
res = is_cgi_installed_ka(item:"guestbook.pl", port:port);
if(res)security_hole(port);

   
