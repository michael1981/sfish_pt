#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(12007);
  script_version ("$Revision: 1.8 $");
  script_cve_id("CVE-2004-2026");
  script_bugtraq_id(10267);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"5746");
  }
  script_name(english: "APSIS Pound Load Balancer Format String Overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote server is vulnerable to a remote format string bug which can
allow remote attackers to gain access to confidential data.  
Pound versions less than 1.6 are vulnerable to this issue." );
 script_set_attribute(attribute:"see_also", value:"http://www.apsis.ch/pound/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to at least version 1.6 of APSIS Pound." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "APSIS Pound Load Balancer Format String Overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start script
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

r = http_send_recv3(method: "GET", port: port, item: "/%s");

if (r[0] =~ "^HTTP/1\.[01] 503 ")
{
  r = http_send_recv3(method: "GET", port: port, item: "/%s %s %s");
# this test is classified as DESTRUCTIVE, but the service *does* restart 
# automagically.
# you'll see something like this in your logs
# pound: MONITOR: worker exited on signal 11, restarting...
  if (isnull(r)) security_hole(port);
}
