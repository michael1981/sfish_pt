#
# (C) Tenable Network Security
#

include( 'compat.inc' );

if(description)
{
  script_id(14194);
  script_version ("$Revision: 1.7 $");
  script_cve_id("CVE-2004-2056");
  script_bugtraq_id(10798);
  script_xref(name:"OSVDB", value:"8258");

  script_name(english:"Nucleus CMS action.php itemid Parameter SQL Injection");
  script_summary(english:"Nucleus Version Check");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is prone to a SQL injection.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running Nucleus CMS, an open-source content management
system.

There is a SQL injection condition in the remote version of this software
which may allow an attacker to execute arbitrary SQL commands against
the remote database.

An attacker may exploit this flaw to gain unauthorized access to the remote
database and gain admin privileges on the remote CMS."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Nucleus 3.1 or newer."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=109087144509299&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:"/index.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ('"generator" content="Nucleus' >< res )
 {
     line = egrep(pattern:"generator.*content=.*Nucleus v?([0-9.]*)", string:res);
     version = ereg_replace(pattern:".*generator.*content=.*Nucleus v?([0-9.]*).*", string:line);
     if ( version == line ) version = "unknown";
     if ( dir == "" ) dir = "/";

     set_kb_item(name:"www/" + port + "/nucleus", value:version + " under " + dir );

    if ( ereg(pattern:"^([0-2]|3\.0)", string:version) )
    {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
     exit(0);
    }
 }
}
