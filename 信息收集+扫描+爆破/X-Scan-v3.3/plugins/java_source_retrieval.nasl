#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(12245);
 script_version ("$Revision: 1.7 $");
 
 script_name(english:"Java (.java / .class) Source Code Disclosure");
 script_summary(english:"Java Source Code Disclosure check");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server is disclosing potentially sensitive data."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote web server is hosting Java (.java and/or .class) files.\n",
     "These files may contain sensitive or proprietary information.  If so,\n",
     "a remote attacker could use this information to mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Restrict access to any sensitive data."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# start script

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(! get_port_state(port))
	exit(0);

init = get_kb_list(string("www/", port, "/java_classfile"));

if (isnull(init)) 
	exit(0);


master = make_list(init);
mylist = make_list();


# Ensure that web server doesn't respond with '200 OK' for everything
req = http_get(item:string("Nessus", rand() % 65535, ".class"), port:port);
soc = http_open_socket(port);
if (!soc) 
	exit(0);

send (socket:soc, data:req);
res = recv_line(socket:soc, length:512);
http_close_socket(soc);

if (! res || ("200 OK" >< res) ) 
	exit(0);


vcounter = 0;

foreach script (master) 
{
    if ( (".class" >< tolower(script)) || (".java" >< tolower(script)) ) 
    {
        rootname = ereg_replace(string:script, pattern:"\.class|\.java", replace:"", icase:TRUE);
    } 
    else 
    {
        rootname = script;
    }

    req  = http_get(item:string(rootname, ".class"), port:port);
    req2 = http_get(item:string(rootname, ".java"),  port:port);

    if ("http://" >!< req)  
    {
	res  = http_keepalive_send_recv(port:port, data:req);
        if (res == NULL) 
		exit(0);
    }

    if ("http://" >!< req2) 
    {
	res2 = http_keepalive_send_recv(port:port, data:req2);
        if (res == NULL)
		exit(0);
    }

    if (egrep(string:res, pattern:"^HTTP/.* 200 OK"))
    {
	mylist = make_list(mylist, string(rootname, ".class")); 
	vcounter++;
    }

    if (egrep(string:res2, pattern:"^HTTP/.* 200 OK"))
    {
	mylist = make_list(mylist, string(rootname, ".java") ); 
	vcounter++;
    }

    if (vcounter > 20) 
	break;        

    res = res2 = req = req2 = rootname = NULL;
}

if (vcounter) 
{
    report = string("\nNessus was able to download the following files :\n\n");

    foreach file (mylist) 
        report += string(file,"\n");

    security_warning(port:port, extra:report);
}




