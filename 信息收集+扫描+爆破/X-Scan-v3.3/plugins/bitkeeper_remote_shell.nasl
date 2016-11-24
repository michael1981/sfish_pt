#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11198);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(6588, 6589, 6590);
 script_xref(name:"OSVDB", value:"50549");
 script_xref(name:"OSVDB", value:"50550");
 script_xref(name:"Secunia", value:"7854");

 script_name(english:"BitKeeper Daemon Mode diff Shell Command Injection");
 script_summary(english:"Checks for the remote banner");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote revision control server has a remote command\n",
     "execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host is running version 3.0.x of BitKeeper.\n",
     "Some versions of this service are known to allow anyone execute\n",
     "arbitrary commands with the privileges of the BitKeeper daemon.\n\n",
     "*** Nessus did not check for this vulnerability, but solely\n",
     "*** relied on the banner of the remote server to issue this warning\n\n",
     "BitKeeper is also reportedly vulnerable to a race condition\n",
     "involving temporary file creation.  Nessus did not check for this issue."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0018.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BitKeeper."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/BitKeeper");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 
 # The original exploit says that the bug can be exploited
 # by doing : http://host:port/diffs/foo.c@%27;echo%20%3Eiwashere%27?nav=index.html|src/|hist/foo.c
 # but since no repository is given, I'm a bit surprised. 
 # At this time, we'll simply yell if we see the banner
 #
 if("Server: bkhttp/0.3" >< banner)security_hole(port);
