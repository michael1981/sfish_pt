#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(22268);
  script_version("$Revision: 1.9 $");

  script_cve_id(
    "CVE-2006-0996",
    "CVE-2006-1490", 
    "CVE-2006-1494", 
    "CVE-2006-1608",
    "CVE-2006-1990",
    "CVE-2006-1991",
    "CVE-2006-2563",
    "CVE-2006-2660",
    "CVE-2006-3011",
    "CVE-2006-3016", 
    "CVE-2006-3017", 
    "CVE-2006-3018"
  );
  script_bugtraq_id(17296, 17362, 17439, 17843, 18116, 18645);
  script_xref(name:"OSVDB", value:"24248");
  script_xref(name:"OSVDB", value:"24484");
  script_xref(name:"OSVDB", value:"25253");
  script_xref(name:"OSVDB", value:"25254");
  script_xref(name:"OSVDB", value:"25255");
  script_xref(name:"OSVDB", value:"26827");

  script_name(english:"PHP < 4.4.3 / 5.1.4 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.3 / 5.1.4.  Such versions may be affected by
several issues, including a buffer overflow, heap corruption, and a
flaw by which a variable may survive a call to 'unset()'." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/20060409192313.20536.qmail@securityfocus.com" );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/442437/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_4_4_3.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_5_1_3.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_5_1_4.php" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.3 / 5.1.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


banner = get_http_banner(port:port);
if (banner)
{
  ver = get_php_version(banner:banner);
  if (ver && ver =~ "PHP/(3\.|4\.([0-3]\.|4\.[0-2])|5\.(0\.|1[0-3]))")
  {
    if (report_verbosity)
    {
      ver = strstr(ver, "PHP/") - "PHP/";
      report = string(
        "\n",
        "PHP version ", ver, " appears to be running on the remote host based on\n"
      );

      if (egrep(pattern:"Server:.*PHP/[0-9].", string:banner))
      {
        line = egrep(pattern:"Server:.*PHP/[0-9].", string:banner);
        report = string(
          report, 
          "the following Server response header :\n",
          "\n",
          "  ", line
        );
      }
      else if (egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:banner))
      {
        line = egrep(pattern:"^X-Powered-By:.*PHP/[0-9]", string:banner);
        report = string(
          report, 
          "the following X-Powered-By response header :\n",
          "\n",
          "  ", line
        );
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
