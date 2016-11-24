#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11796);
 script_bugtraq_id(8126, 8127, 8128);
 script_xref(name:"OSVDB", value:"2292");
 script_xref(name:"Secunia", value:"9253");
 script_version ("$Revision: 1.8 $");

 script_name(english:"Forum51/Board51/News51 Users Disclosure");
 script_summary(english:"Checks for the presence of user.idx");
 
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
     "The remote web server is running a bulletin board application\n",
     "(Forum51, Board51, or News51) with an information disclosure\n",
     "vulnerability.  It is possible to retrieve usernames and password\n",
     "hashes by requesting '/data/user.idx'.  A remote attacker could use\n",
     "this information to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-07/0078.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Restrict public access to the '/data' directory."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
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

#
# The script code starts here
#
port = get_http_port(default:80);
dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 url = string(dir, "/forumdata/data/user.idx");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(1, "The server didn't respond.");

 body = res[2];
 url = string(dir, "/boarddata/data/user.idx");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(1, "The server didn't respond.");

 body += res[2];
 url = string(dir, "/newsdata/data/user.idx");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(1, "The server didn't respond.");

 body += res[2];

 if (
   egrep(pattern:"^.*;.*@.*;[0-9]*;.*;[0-9]*;[0-9]*;.*", string:body) ||
   egrep(pattern:"^[0-9]*;.*;.*;.*@.*", string:body)
 )
 {
   security_warning(port);
   exit(0);
 }
}
