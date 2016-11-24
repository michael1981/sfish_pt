#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10004);
 script_version ("$Revision: 1.30 $");

 script_cve_id("CVE-1999-0449");
 script_bugtraq_id(193);
 script_xref(name:"OSVDB", value:"2");

 script_name(english:"Microsoft IIS search.asp Direct Request DoS");
 script_summary(english:"Determines the presence of an ExAir asp");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server is prone to a denial of service attack."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote instance of IIS includes the sample site 'ExAir'.  By\n",
   "calling one of the included Active Server Pages, specifically\n",
   "'/iissamples/exair/search/search.asp', an unauthenticated remote\n",
   "attacker may be cause the web server to hang for up to 90 seconds (the\n",
   "default script timeout) if the default ExAir page and associated dlls\n",
   "have not been loaded into the IIS memory space."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0336.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Delete the 'ExAir' sample IIS site."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P"
 );
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"1999/01/26"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"1999/06/22"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


cgi = "/iissamples/exair/search/search.asp";
ok = is_cgi_installed3(item:cgi, port:port);
if(ok)security_warning(port);

