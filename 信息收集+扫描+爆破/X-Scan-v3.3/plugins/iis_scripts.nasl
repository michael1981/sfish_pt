#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10121);
 script_version ("$Revision: 1.24 $");

 script_xref(name:"OSVDB", value:"3268");

 script_name(english:"Microsoft IIS /scripts Directory Browsable");
 
 # Description
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulneraiblity." );
 script_set_attribute(attribute:"description", value:
"The /scripts directory is browsable.  This gives an attacker valuable
information about which default scripts you ahve installed and also
wehther there are any custom script present which may have
vulnerabilities." );
 script_set_attribute(attribute:"solution", value:
"Disable directory browsing using the IIS MMC." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 script_summary(english:"Is /scripts/ listable ?");
 script_category(ACT_GATHER_INFO);
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);
if(get_port_state(port))
{
  res = http_send_recv3(method:"GET", item:"/scripts", port:port);
  if (isnull(res)) exit(1, "The remote web server did not respond.");

  if ((" 200 " >< res[1]) && ("<title>/scripts" >< res[2])) security_warning(port:port);
}
