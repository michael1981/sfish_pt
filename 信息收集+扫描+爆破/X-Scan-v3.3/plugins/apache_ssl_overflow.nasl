#
# (C) Tenable Network Security, Inc.
#

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>,
# with the impulsion of H D Moore on the Nessus Plugins-Writers list
#


include("compat.inc");

if(description)
{
 script_id(10918);
 script_version("$Revision: 1.18 $");
 script_bugtraq_id(4189);
 script_cve_id("CVE-2002-0082");
 script_xref(name:"OSVDB", value:"756");
 
 script_name(english:"Apache-SSL < 1.3.23+1.46 i2d_SSL_SESSION Function SSL Client Certificate Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using a version of Apache-SSL which is older than
1.3.22+1.46.  Such versions are vulnerable to a buffer overflow that,
albeit difficult to exploit, may allow an attacker to execute
arbitrary commands on this host subject to the privileges under which
the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache-ssl.org/advisory-20020301.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-02/0313.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0000.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-03/0012.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache-SSL version 1.3.23+1.47 or newer.  [Note that the
vulnerability was initially addressed in 1.3.23+1.46 but that version
had a bug.]" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for version of Apache-SSL";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port = get_http_port(default:80);

 banner = get_backport_banner(banner:get_http_banner(port: port));
 if (!banner) exit(0);
 
 server = strstr(banner, "Server:");
 server = server - strstr(server, '\r\n');
 if (" Ben-SSL/" >< server)
 {
  ver = NULL;

  pat = "^Server:.*Apache(-AdvancedExtranetServer)?/.* Ben-SSL/([0-9]+\.[0-9]+)";
  item = eregmatch(pattern:pat, string:server);
  if (!isnull(item)) ver = item[2];

  if (!isnull(ver) && ver =~ "^1\.([0-9]($|[^0-9])|([0-3][0-9]|4[0-5])($|[^0-9]))")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "The remote Apache-SSL server uses the following Server response\n",
        "header :\n",
        "\n",
        "  ", server, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
 }

