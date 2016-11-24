#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11972);
 script_version ("$Revision: 1.13 $");
 script_bugtraq_id(9310);
 script_xref(name:"OSVDB", value:"3304");
 script_xref(name:"Secunia", value:"10517");

 script_name(english:"miniBB bb_func_usernfo.php Website Name Field XSS");
 script_summary(english:"Determine if MiniBB can be used to execute arbitrary commands");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a cross-site scripting\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is using the miniBB forum management system.\n",
     "According to its version number, this forum is vulnerable to a\n",
     "cross-site scripting bug.  A remote attacker could exploit\n",
     "this to impersonate a legitimate user by tricking them into\n",
     "requesting a maliciously crafted URL."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q4/3822.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");

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
if(!can_host_php(port:port)) exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/index.php");
 buf = http_get_cache(item:url, port:port);
 if (isnull(buf)) exit(1, "The web server didn't respond");

 str = egrep(pattern:"Powered by.*miniBB", string:buf);
 if( str )
   {
    version = ereg_replace(pattern:".*Powered by.*miniBB (.*)</a>.*", string:str, replace:"\1");
    if ( d == "" ) d = "/";

    set_kb_item(name:"www/" + port + "/minibb", value:version + " under " + d);

    if ( ereg(pattern:"^(0\.|1\.[0-6][^0-9]|7[^a-z])", string:version) )
     {
     security_warning(port);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
     exit(0);
     }
   }
}
