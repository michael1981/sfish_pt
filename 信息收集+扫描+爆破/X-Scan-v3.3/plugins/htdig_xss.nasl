#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Howard Yeend <h_bugtraq@yahoo.com>
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised plugin title (2/08/2009)


include("compat.inc");

if(description)
{
 script_id(15706);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2002-2010");
 script_bugtraq_id(5091);
 script_xref(name:"OSVDB", value:"7590");
 
 script_name(english:"ht://Dig htsearch.cgi words Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote contains a search engine that is affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'htsearch' CGI, which is part of the ht://Dig package, is 
vulnerable to cross-site scripting attacks, through the 'words' 
variable.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-06/0321.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks if ht://Dig is vulnerable to XSS flaw in htsearch.cgi");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);
if ( ! port ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
   foreach dir (cgi_dirs())
   {
  	buf = http_get(item:string(dir,"/htsearch.cgi?words=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);
  	r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  	if( r == NULL )exit(0);
  	if(egrep(pattern:"<script>foo</script>", string:r))
  	{
    		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 	exit(0);
  	}
   }
}
