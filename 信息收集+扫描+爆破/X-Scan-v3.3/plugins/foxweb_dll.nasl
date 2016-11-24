#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11939);
 script_version ("$Revision: 1.12 $");

 script_cve_id("CVE-2003-0762");
 script_bugtraq_id(8547);
 script_xref(name:"OSVDB", value:"11740");
 script_xref(name:"OSVDB", value:"11741");

 script_name(english:"Foxweb foxweb.exe / foxweb.dll Long URL Remote Overflow");
 script_summary(english:"Checks for the presence of foxweb.exe or foxweb.dll");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host is prone to buffer\n",
     "overflow attacks."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The foxweb.dll or foxweb.exe CGI is installed.\n\n",
     "Versions 2.5 and below of this CGI program have a remote stack buffer\n",
     "overflow.  A remote attacker could use this to crash the web server,\n",
     "or possibly execute arbitrary code.\n\n",
     "** Since Nessus just verified the presence of the CGI but could\n",
     "** not check the version number, this might be a false alarm."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q3/0096.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Unknown at this time."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
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

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

l = make_list("foxweb.dll", "foxweb.exe");
foreach cgi (l)
{
  res = is_cgi_installed3(item:cgi, port:port);
  if(res)
  {
    security_hole(port);
    exit(0);	# As we might fork, we exit here
  }
}
