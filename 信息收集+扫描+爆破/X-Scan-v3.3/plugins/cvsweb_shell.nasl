#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10465);
 script_bugtraq_id(1469);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0670");
 script_xref(name:"OSVDB", value:"364");
 script_name(english:"CVSweb 1.80 cvsweb.cgi Arbitrary Command Execution");
 script_summary(english:"Checks if CVSweb is present and gets its version");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The web application running on the remote host has a command\n",
     "execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The version of CVSweb on the remote host is <= 1.85.  This version\n",
     "allows a remote attacker to execute arbitrary commands in the context\n",
     "of the web server.\n\n",
     "This version of CVSweb is no longer maintained.  Please consider\n",
     "switching to the latest version of FreeBSD CVSweb."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/freebsd/2000-08/0096.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.freebsd.org/projects/cvsweb.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Switch to the latest version of CVSweb."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
  
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "cvsweb_version.nasl");
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

 name = string("www/", port, "/cvsweb/version");
 version = get_kb_item(name);
 if(version)
 {
 if(ereg(pattern:"^1\.([0-7].*|8[0-5])[^0-9]",
         string:version))
	 	security_hole(port);
 }
