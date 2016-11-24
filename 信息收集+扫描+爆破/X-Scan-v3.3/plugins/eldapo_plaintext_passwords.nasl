#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11758);
 script_version ("$Revision: 1.10 $");
 script_bugtraq_id(7535);
 
 script_name(english:"eLDAPo index.php Cleartext Password Disclosure");
 script_summary(english:"Checks for eLDAPo");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has an information\n",
     "disclosure vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is hosting eLDAPo, a PHP-based CGI suite designed\n",
     "to perform LDAP queries.\n\n",
     "This application stores the passwords to the LDAP server in clear\n",
     "text in its source file. An attacker could read the source code of\n",
     "index.php and may use the information contained to gain credentials\n",
     "on a third party server."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgade to eLDAPo 1.18 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/listing.php");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(0);

 if ("images/eLDAPo.jpg" >< res[2])
 {
  if(egrep(pattern:".*images/eLDAPo\.jpg.*V (0\.|1\.([0-9][^0-9]|1[0-7][^0-9]))", 
  	   string:res[2]))
	   {
	    security_warning(port);
	   }
     exit(0);	   
 }
}
