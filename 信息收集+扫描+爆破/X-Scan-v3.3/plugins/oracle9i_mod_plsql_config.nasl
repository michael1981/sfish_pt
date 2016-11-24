#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11452);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2002-0561");
 script_bugtraq_id(4292);
 script_xref(name:"OSVDB", value:"9472");
 script_xref(name:"IAVA", value:"2002-t-0006");

 script_name(english:"Oracle 9iAS PL/SQL Gateway Web Admin Interface Null Authentication");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"Oracle 9i Application Server uses Apache as its web
server with an Apache module for PL/SQL support.

By default, no authentication is required to access the
DAD configuration page. An attacker may use this flaw
to modify PL/SQL applications or prevent the remote host
from working properly." );

 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/ias_modplsql_alert.pdf" );
 script_set_attribute(attribute:"solution", value:
"Access to the relevant page can be restricted by
editing the file /Apache/modplsql/cfg/wdbsvr.app." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Oracle 9iAS mod_plsql admin page");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 7777);
 script_require_keys("www/OracleApache");
 exit(0);
}

#
# The script code starts here
# 
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:7777);

foreach port (ports)
{
 r = http_send_recv3(method: "GET", item:"/pls/simpledad/admin_/gateway.htm?schema=sample", port:port);
 if(!isnull(r) && "Gateway Configuration" >< r[2])
  security_hole(port); 
}

