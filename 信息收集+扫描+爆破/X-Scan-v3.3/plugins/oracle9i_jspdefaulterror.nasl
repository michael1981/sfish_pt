#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/9/09)

include("compat.inc");

if(description)
{
 script_id(11226);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2001-1372");
 script_bugtraq_id(3341);
 script_xref(name:"OSVDB", value:"5406");

 script_name(english:"Oracle 9iAS Nonexistent .jsp File Request Error Message Path Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the physical path of the remote server web
root." );
 script_set_attribute(attribute:"description", value:
"Oracle 9iAS allows remote attackers to obtain the physical path of a
file under the server root via a request for a nonexistent .JSP file. 
The default error generated leaks the pathname in an error message." );
 script_set_attribute(attribute:"see_also", value:"http://otn.oracle.com/deploy/security/pdf/jspexecute_alert.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/278971" );
 script_set_attribute(attribute:"see_also", value:"http://www.cert.org/advisories/CA-2002-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/papers/hpoas.pdf" );
 script_set_attribute(attribute:"solution", value:
"Ensure that virtual paths of URL is different from the actual directory 
path. Also, do not use the <servletzonepath> directory in 
'ApJServMount <servletzonepath> <servletzone>' to store data or files. 

Upgrading to Oracle 9iAS 1.1.2.0.0 will also fix this issue." );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
 script_end_attributes();

 script_summary(english:"Tries to retrieve the phisical path of files through Oracle9iAS");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Javier Fernandez-Sanguino");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for the configuration file

     errorjsp = "/nonexistent.jsp";
     req = http_get(item: errorjsp, port: port);
     soc = http_open_socket(port);
     if(soc) {
        send(socket:soc, data:req);
         r = http_recv(socket:soc);
         http_close_socket(soc);
         location = egrep(pattern:"java.io.FileNotFoundException:", string :r);
         if ( location )  {
	   foreach line (split(location, keep:FALSE)) {
	     path = strstr(line, "java.io.FileNotFoundException:") - "java.io.FileNotFoundException:";
	     while (strlen(path) && path[0] == ' ')
	       path = substr(path, 1);
	     if (substr(errorjsp, 1) >< path) {
	       path = path - strstr(path, substr(errorjsp, 1));
	       if (path =~ "[/\\]$") path = substr(path, 0, strlen(path)-2);
	     }
	   }
	   if (strlen(path) && path !~ '^ +$') {
	     security_warning(port:port, data: 'The web root physical path is :\n\n  '+ path+'\n');
	     exit(0);
	   }
	 }
     } # if (soc)
}
