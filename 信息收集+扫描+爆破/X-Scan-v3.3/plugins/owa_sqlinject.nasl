#
# This script was written by Michael J. Richardson <michael.richardson@protiviti.com>
# Vulnerability identified by Donnie Werner of Exploitlabs Research Team
#

# Changes by Tenable:
# - Revised plugin title, changed family (5/21/09)


include("compat.inc");

if(description)
{
  script_id(17636);
  script_version ("$Revision: 1.12 $");
  script_cve_id("CVE-2005-0420");
  script_bugtraq_id(12459);
  script_xref(name:"OSVDB", value:"13621");

  script_name(english:"Microsoft Outlook Web Access (OWA) owalogon.asp Redirection Account Enumeration");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a URL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Outlook Web Access 2003. 

Due to a lack of sanitization of the user input, the remote version of
this software is vulnerable to URL injection that can be exploited to
redirect a user to a different, unauthorized web server after
authenticating to OWA.  This unauthorized site could be used to
capture sensitive information by appearing to be part of the web
application." );
 script_set_attribute(attribute:"see_also", value:"http://exploitlabs.com/files/advisories/EXPL-A-2005-001-owa.txt" );
 script_set_attribute(attribute:"solution", value:
"None at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 script_summary(english:"The remote host is running Microsoft Outlook Web Access 2003 and is vulnerable to URL Injection.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Michael J. Richardson");
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

port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);

req = http_get(item:string("/exchweb/bin/auth/owalogon.asp?url=http://12345678910"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) &&  
   "owaauth.dll" >< res && 
   '<INPUT type="hidden" name="destination" value="http://12345678910">' >< res)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
