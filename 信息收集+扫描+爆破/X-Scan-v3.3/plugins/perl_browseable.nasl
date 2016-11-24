#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10511);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0883");
 script_bugtraq_id(1678);
 script_xref(name:"OSVDB", value:"410");

 script_name(english:"mod_perl for Apache HTTP Server /perl/ Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information  
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The /perl directory is browsable.
This will show you the name of the installed common perl scripts and 
those which are written by the webmaster and thus may be exploitable." );
 script_set_attribute(attribute:"solution", value:
"Make the /perl non-browsable (in httpd.conf or mod_perl.conf)" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();
 
 script_summary(english:"Is /perl browsable ?");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

r = http_send_recv3(method: "GET", item:"/perl/", port:port);
if (isnull(r)) exit(1, "Server did not answer");

if (" 200 " >< r[0])
{
  buf = tolower(r[2]);
  must_see = "index of /perl";

  if (must_see >< buf)
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/content/directory_index', value: '/perl:');
  }
}

