#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10478);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0760");
 script_bugtraq_id(1532);
 script_xref(name:"OSVDB", value:"377");

 script_name(english:"Apache Tomcat Snoop Servlet Remote Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a servlet installed that is 
affected by an information diclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'snoop' tomcat's servlet is installed.
(/examples/jsp/snp/anything.snp)

This servlet gives too much information about 
the remote host, such as the PATHs in use,
the host kernel version and so on...

This allows an attacker to gain more knowledge
about this host, and make more precise attacks
thanks to this." );
 script_set_attribute(attribute:"solution", value:
"Delete this servlet." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /examples/jsp/snp/anything.snp");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

res = http_send_recv3(method:"GET", item:"/examples/jsp/snp/anything.snp", port:port);

if(ereg(pattern:"HTTP/[0-9]\.[0-9] 200 ", string:res[2]))
{
  if("Server Info: Tomcat" >< res[2])
  {
   security_warning(port);
  }
}
