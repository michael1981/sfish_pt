#
# (C) Tenable Network Security, Inc.
#

# Thanks to Sullo who supplied a sample of WebLogic banners

include( 'compat.inc' );

if(description)
{
  script_id(11486);
  script_version ("$Revision: 1.12 $");
  script_cve_id("CVE-2003-0151", "CVE-2003-1095");
  script_bugtraq_id(7122, 7124, 7130, 7131);
  script_xref(name:"OSVDB", value:"10340");
  script_xref(name:"OSVDB", value:"16025");

  script_name(english:"WebLogic Servlets Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WebLogic");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web server is prone to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server is WebLogic.

An internal management servlet which does not properly
check user credential can be accessed from outside, allowing
a cracker to change user passwords, and even upload or download
any file on the remote server.

In addition to this, there is a flaw in WebLogic 7.0 which may
allow users to delete empty subcontexts.

*** Note that Nessus only checked the version in the server banner
*** So this might be a false positive."
  );

  script_set_attribute(
    attribute:'solution',
    value: "- Apply Service Pack 2 Rolling Patch 3 on WebLogic 6.0
- Apply Service Pack 4 on WebLogic 6.1
- Apply Service Pack 2 on WebLogic 7.0 or 7.0.0.1"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-28.jsp'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/weblogic");
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);

if ("WebLogic " >!< banner) exit(0);	 # Not WebLogic

# All those tests below have NEVER been validated!
# Here are the banner we got:
# WebLogic 5.1.0 04/03/2000 17:13:23 #66825
# WebLogic 5.1.0 Service Pack 10 07/11/2001 21:04:48 #126882
# WebLogic 5.1.0 Service Pack 12 04/14/2002 22:57:48 #178459
# WebLogic 5.1.0 Service Pack 6 09/20/2000 21:03:19 #84511
# WebLogic 5.1.0 Service Pack 9 04/06/2001 12:48:33 #105983 - 128 bit domestic version
# WebLogic WebLogic Server 6.1 SP1  09/18/2001 14:28:44 #138716
# WebLogic WebLogic Server 6.1 SP3  06/19/2002 22:25:39 #190835
# WebLogic WebLogic Temporary Patch for CR067505 02/12/2002 17:10:21

# I suppose that this kind of thing might exist
if (" Temporary Patch for CR096950" >< banner) exit(0);

if (banner =~ "WebLogic .* 6\.1 ")
{
  if (" SP4 " >!< banner) security_hole(port);
  exit(0);
}

if (banner =~ "WebLogic .* 6\.0 ")
{
  if (banner !~ " SP[3-9] " && " SP2 RP3 " >!< banner) security_hole(port);
  exit(0);
}

if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  if (banner !~ " SP[2-9]") security_hole(port);
  exit(0);
}
