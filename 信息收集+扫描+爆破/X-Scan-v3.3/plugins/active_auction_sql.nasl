#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(17989);
 script_cve_id("CVE-2005-1029", "CVE-2005-1030");
 script_bugtraq_id(13039, 13038, 13036, 13035, 13034, 13032);
 script_xref(name:"OSVDB", value:"15281");
 script_xref(name:"OSVDB", value:"15282");
 script_xref(name:"OSVDB", value:"15283");
 script_xref(name:"OSVDB", value:"15284");
 script_xref(name:"OSVDB", value:"15285");
 script_xref(name:"OSVDB", value:"15286");
 script_xref(name:"OSVDB", value:"15287");

 script_version("$Revision: 1.9 $");
 script_name(english:"Active Auction Multiple Vulnerabilities (SQLi, XSS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server contains a ASP script that is affected by various
issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Active Auction, an auction software written
in ASP. 

The remote version of this software is affected by various SQL
injection and cross-site scripting issues." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-04/0079.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Checks for a SQL injection error in Active Auction House";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0);


foreach dir (make_list( cgi_dirs()))
{
 r = http_send_recv3(method:"GET",item:dir + "/activeauctionsuperstore/ItemInfo.asp?itemID=42'", port:port);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);

 if(egrep(pattern:"Microsoft.*ODBC.*80040e14", string:res ) )
  {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
  }
}
