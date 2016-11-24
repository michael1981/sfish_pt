#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(31654);
 script_cve_id("CVE-2006-3747");
 script_bugtraq_id(19204);
 script_xref(name:"OSVDB", value:"27588");
 script_version("$Revision: 1.7 $");
 
 script_name(english:"Apache < 1.3.37 mod_rewrite LDAP Protocol URL Handling Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote version of Apache is vulnerable to an off-by-one buffer
overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of Apache which is
older than 1.3.37. 

This version contains an off-by-one buffer overflow in the mod_rewrite
module." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-July/048265.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_1.3" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-July/048269.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.3.37 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for version of Apache";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
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

banner = get_http_banner(port: port);
if(!banner)exit(0);
banner = get_backport_banner(banner:banner);
 
if (banner && "Server:" >< banner)
{
  if (report_paranoia < 2 && backported) exit(0);
  server = strstr(banner, "Server:");

  pat = "^Server:.*Apache(-AdvancedExtranetServer)?/([0-9]+\.[^ ]+)";
  ver = NULL;
  matches = egrep(pattern:pat, string:server);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[2];
        break;
      }
    }
  }

  if (!isnull(ver) && ver =~ "^1\.3\.(2[89]|3[0-6])($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "According to its banner, Apache version ", ver, " is installed on the\n",
        "remote host.\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
