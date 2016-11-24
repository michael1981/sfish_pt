#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11505);
 script_bugtraq_id(6971);
 script_cve_id("CVE-2003-0162");
 script_xref(name:"OSVDB", value:"9796");
 
 script_version ("$Revision: 1.10 $");

 script_name(english:"Ecartis HTML Field Manipulation Arbitrary User Password Reset");
 script_summary(english:"Checks for the presence of lsg2.cgi");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has an arbitrary password\n",
     "reset vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running the Ecartis Mailing List Manager web\n",
     "interface (lsg2.cgi).\n\n",
     "According to its version number, there is a vulnerability that allows\n",
     "an authenticated user to change anyone's password, including the list\n",
     "administrators.  An authenticated attacker could exploit this to take\n",
     "control of the mailing list."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-02/0358.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0035.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Upgrade to an Ecartis Mailing List Manager snapshot version after\n",
     "20030227."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

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

foreach dir (list_uniq(make_list("/ecartis", cgi_dirs())))
{
 url = string(dir, "/lsg2.cgi");
 res = http_send_recv3(method:"GET", item:url, port:port);

 if(isnull(res)) exit(0);

 if(egrep(pattern:"Ecartis (0\..*|1\.0\.0)", string:res[2]))
 	{
	security_warning(port);
	exit(0);
	}
}
