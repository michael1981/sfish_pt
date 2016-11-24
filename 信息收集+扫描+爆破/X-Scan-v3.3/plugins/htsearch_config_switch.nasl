#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10784);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0834");
 script_bugtraq_id(3410);
 script_xref(name:"OSVDB", value:"654");
 script_xref(name:"OSVDB", value:"7591");
 
 script_name(english:"ht://Dig htsearch Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web search engine that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote CGI htsearch allows the user to supply his own
configuration file using the '-c' switch, as in :

	/cgi-bin/htsearch?-c/some/config/file

This file is not displayed by htsearch. However, if an
attacker manages to upload a configuration file to the remote 
server, it may make htsearch read arbitrary files on the remote host.

An attacker may also use this flaw to exhaust the resources on the
remote host by specifying /dev/zero as a configuration file." );
 script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2001-139.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2001/dsa-080" );
 script_set_attribute(attribute:"see_also", value:"ftp://ftp.sco.com/pub/security/OpenLinux/CSSA-2001-035.0.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7ee9854" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ht://Dig 3.1.6 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P" );

script_end_attributes();


 script_summary(english:"htsearch?-c/nonexistent");

 script_family(english:"CGI abuses");
  
 script_category(ACT_GATHER_INFO);
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
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
 res = http_send_recv3(method:"GET", item:string(dir, "/htsearch?-c/nonexistent"), port:port);
 if (isnull(res)) exit(1, "The web server did not respond to the GET request");
 if("Unable to read configuration file '/nonexistent'" >< buffer)
 {
   security_warning(port);
   exit(0);
 }
}

