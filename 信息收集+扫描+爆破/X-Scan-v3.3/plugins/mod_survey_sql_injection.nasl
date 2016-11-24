#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11609);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(7192);
 script_xref(name:"OSVDB", value:"4568");
 script_xref(name:"Secunia", value:"11196");

 script_name(english:"mod_survey For Apache ENV Tags SQL Injection");
 script_summary(english:"mod_survey SQL injection");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web server module on the remote host has a SQL injection\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "According to the banner, the remote host is using a vulnerable\n",
     "version of mod_survey, a Perl module for managing online surveys.\n",
     "This version has a flaw that could result in a SQL injection attack\n",
     "when the module is being used with a database backend.  A remote\n",
     "attacker could exploit this to take control of the database."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to mod_survey 3.0.14e / 3.0.15pre6 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
 
port = get_http_port(default:80);
files = get_kb_list(string("www/",port, "/content/extensions/survey"));
if (isnull(files)) exit(0);

files = make_list(files);
res = http_send_recv3(method:"GET", item:files[0], port:port);
if (isnull(res)) exit(0);

res = res[0] + res[1] + res[2];

if ("Mod_Survey" >< res)
{
  if (egrep(pattern:"Mod_Survey v([0-2]\.|3\.0\.([0-9][^0-9]|1[0-3]|14[^a-z]|14[a-d]|15pre[0-5]))", string:res))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
