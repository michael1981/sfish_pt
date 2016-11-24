#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35043);
  script_version("$Revision: 1.14 $");

  script_cve_id(
    "CVE-2008-2371",
    "CVE-2008-2665",
    "CVE-2008-2666",
    "CVE-2008-2829",
    "CVE-2008-3658",
    "CVE-2008-3659",
    "CVE-2008-3660",
    "CVE-2008-5557",
    "CVE-2008-5624",
    "CVE-2008-5625",
    "CVE-2008-5658"
  );
  script_bugtraq_id(
    29796,
    29797,
    29829,
    30087,
    30649,
    31612,
    32383,
    32625,
    32688,
    32948
    # 33498         nb: retired 29-Jan-2009
  );
  script_xref(name:"OSVDB", value:"46584");
  script_xref(name:"OSVDB", value:"46638");
  script_xref(name:"OSVDB", value:"46639");
  script_xref(name:"OSVDB", value:"46641");
  script_xref(name:"OSVDB", value:"46690");
  script_xref(name:"OSVDB", value:"47796");
  script_xref(name:"OSVDB", value:"47797");
  script_xref(name:"OSVDB", value:"47798");
  script_xref(name:"OSVDB", value:"50480");
  script_xref(name:"OSVDB", value:"51477");
  script_xref(name:"OSVDB", value:"52205");
  script_xref(name:"OSVDB", value:"52206");
  script_xref(name:"OSVDB", value:"52207");

  script_name(english:"PHP 5 < 5.2.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.7.  Such versions may be affected by several
security issues :

  - File truncation can occur when calling 'dba_replace()'
    with an invalid argument.

  - There is a buffer overflow in the bundled PCRE library
    fixed by 7.8. (CVE-2008-2371)

  - A buffer overflow in the 'imageloadfont()' function in
    'ext/gd/gd.c' can be triggered when a specially crafted
    font is given. (CVE-2008-3658)

  - There is a buffer overflow in PHP's internal function
    'memnstr()', which is exposed to userspace as 
    'explode()'. (CVE-2008-3659)

  - When used as a FastCGI module, PHP segfaults when 
    opening a file whose name contains two dots (eg, 
    'file..php'). (CVE-2008-3660)

  - Multiple directory traversal vulnerabilities in 
    functions such as 'posix_access()', 'chdir()', 'ftok()'
    may allow a remote attacker to bypass 'safe_mode' 
    restrictions. (CVE-2008-2665 and CVE-2008-2666).

  - A buffer overflow may be triggered when processing long
    message headers in 'php_imap.c' due to use of an 
    obsolete API call. (CVE-2008-2829)

  - A heap-based buffer overflow may be triggered via
    a call to 'mb_check_encoding()', part of the 'mbstring'
    extension. (CVE-2008-5557)

  - Missing initialization of 'BG(page_uid)' and 
    'BG(page_gid)' when PHP is used as an Apache module 
    may allow for bypassing security restriction due to
    SAPI 'php_getuid()' overloading. (CVE-2008-5624)

  - Incorrect 'php_value' order for Apache configuration
    may allow bypassing PHP's 'safe_mode' setting.
    (CVE-2008-5625)

  - The ZipArchive:extractTo() method in the ZipArchive
    extension fails to filter directory traversal 
    sequences from file names. (CVE-2008-5658)" );
 script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/57" );
 script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/58" );
 script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/59" );
 script_set_attribute(attribute:"see_also", value:"http://www.sektioneins.de/advisories/SE-2008-06.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-06/0238.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-06/0239.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/08/08/2" );
 script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2008/08/13/8" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-11/0433.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2008-12/0089.html" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=42862" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=45151" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=45722" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_7.php" );
 script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChageLog-5.php#5.2.7" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.8 or later.

Note that 5.2.7 was been removed from distribution because of a
regression in that version that results in the 'magic_quotes_gpc'
setting remaining off even if it was set to on." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
  if (ver && ver =~ "PHP/5\.([01]\.|2\.[0-6]($|[^0-9]))")
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
