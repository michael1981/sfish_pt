#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15982);
 script_version ("$Revision: 1.9 $");

 script_name(english:"phpGroupWare Detection"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a groupware system written in PHP." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPGroupWare, a groupware system written in
PHP." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpgroupware.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();


 summary["english"] = "Checks for PhpGroupWare";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
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
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


function check(url)
{
	local_var r, w, report, version;
	w = http_send_recv3(method: "GET", item:string(url, "/login.php"), port:port);
	if (isnull(w)) exit(0);
	r = w[2];

    	if ("phpGroupWare http://www.phpgroupware.org" >< r)
	{
		version = egrep(pattern:".*phpGroupWare ([0-9.]+).*", string:r);
		if ( version )
		{
		 version = ereg_replace(pattern:".*phpGroupWare ([0-9.]+).*", string:version, replace:"\1");
		 if ( url == "" ) url = "/";
	 	 set_kb_item(name:"www/" + port + "/phpGroupWare", value:version + " under " + url );
    		 {
                   report = string(
                     "\n",
                     "phpGroupWare ", version, " is installed on the remote host under\n",
                     "the path ", url, ".\n"
                   );
                   security_note(port:port, extra:report);
		 }
		}
    	}
}

check(url:"");
check(url:"/phpgroupware/");
check(url:"/phpgw/");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
