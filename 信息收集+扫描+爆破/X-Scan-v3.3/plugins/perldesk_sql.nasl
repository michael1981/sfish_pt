#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16323);
 script_cve_id("CVE-2005-0343");
 script_bugtraq_id(12471);
 script_xref(name:"OSVDB", value:"13623");
 
 script_version ("$Revision: 1.10 $");
 script_name(english: "PerlDesk kb.cgi view Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PerlDesk, a web-based helpdesk application
written in Perl. 

The remote version of this software has several SQL injection
vulnerabilities, which may allow an attacker to execute arbitrary SQL
statements on the remote database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 script_end_attributes();
 
 script_summary(english: "Checks if PerlDesk is vulnerable to a SQL injection attack");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(port: port, method: 'POST', item: dir + "/kb.cgi?view='&lang=en");
 if (isnull(r)) exit(0);
 if("Couldn't execute statement: You have an error in your SQL syntax near ''' at line 1; stopped" >< r[2] )
  {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
  }
}
