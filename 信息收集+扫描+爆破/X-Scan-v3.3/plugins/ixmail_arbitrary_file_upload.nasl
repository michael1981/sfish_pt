#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11781);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(8046, 8048);
 script_xref(name:"OSVDB", value:"53712");
 script_xref(name:"OSVDB", value:"53713");
 
 script_name(english:"iXmail Multiple Script Arbitrary File Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote webmail application is affected by a file upload 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the iXmail webmail interface.

There is a flaw in this interface which allows an attacker who has a
valid account on this host to upload and execute arbitrary php files
on this host, thus potentially gaining a shell on this host. An 
attacker may also use this flaw to delete arbitrary files on the 
remote host, with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpsecure.info/v2/tutos/frog/iXmail.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to iXMail 0.4" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for iXMail");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("misc_func.inc");
include("http.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

foreach dir (list_uniq(make_list("/ixmail", cgi_dirs())))
{
 # Ugly.
 res = http_send_recv3(method:"GET", item:string(dir, "/README.TXT"), port:port);
 if (isnull(res)) exit(1, "The remote web server did not respond.");

 if ("iXmail" >< res[2])
 {
   if (egrep(pattern:".*version.*: 0\.[0-3][^0-9]", string:res[2]))
   {
     security_warning(port);
     exit(0);
   }
 }
}
