#
# (C) Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(16364);
 script_version("$Revision: 1.7 $");
 
 script_cve_id("CVE-2005-0367");
 script_xref(name:"OSVDB", value:"13648");
 script_xref(name:"OSVDB", value:"13649");
 script_xref(name:"OSVDB", value:"13650");

 script_bugtraq_id(12502);

 name["english"] = "ArGoSoft Mail Server Multiple Traversals";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft WebMail interface.  There are
multiple flaws in this interface that may allow an authenticated
attacker to read arbitrary files on the remote server and create /
delete arbitrary directories on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/389866" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft 1.8.7.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Gets the version of the remote ArGoSoft server";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

 res = http_get_cache(item:"/", port:port);
 if( res == NULL ) exit(0);
 if((vers = egrep(pattern:".*ArGoSoft Mail Server.*Version", string:res)))
 {
  if(ereg(pattern:".*Version.*\((0\.|1\.([0-7]\.|8\.([0-6]\.|7\.[0-3])))\)", 
  	  string:vers))security_warning(port);
 }
