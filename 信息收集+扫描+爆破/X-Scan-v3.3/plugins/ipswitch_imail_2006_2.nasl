#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(24782);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-1637");
  script_bugtraq_id(22852);
  script_xref(name:"OSVDB", value:"33648");

  script_name(english:"Ipswitch IMail Server < 2006.2 Multiple Remote Overflows");
  script_summary(english:"Checks version of Ipswitch IMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch Collaboration Suite / IMail,
commercial messaging and collaboration suites for Windows. 

According to its banner, the version of Ipswitch Collaboration Suite /
IMail installed on the remote host has several unspecified buffer
overflows in various service components and ActiveX controls.  An
attacker may be able to leverage these issues to crash the affected
service or even to execute arbitrary code remotely, by default with
LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=487" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2007-03/0021.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ics/updates/ics20062.asp" );
 script_set_attribute(attribute:"see_also", value:"http://support.ipswitch.com/kb/IM-20070305-JH01.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2006.2 of the appropriate application." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Do banner checks of various ports.
#
# - SMTP.
port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
banner = get_smtp_banner(port:port);
if (banner && " (IMail " >< banner)
{
  pat = "^[0-9][0-9][0-9] .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\) NT-ESMTP Server";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if it's < 9.20 (== 2006.2).
  if (ver && ver =~ "^([0-8]\.|9\.(0[0-9]$|1$))")
    security_hole(port);

  # nb: it's possible to customize the banner, but unless thorough checks
  #     are enabled, we'll just stop.
  if (!thorough_tests) exit(0);
}
# - POP3.
port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);
banner = get_pop3_banner(port:port);
if (banner && " (IMail " >< banner)
{
  pat = "NT-POP3 Server .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\)";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if it's < 9.20 (== 2006.2).
  if (ver && ver =~ "^([0-8]\.|9\.(0[0-9]$|1$))")
    security_hole(port);

  # nb: it's possible to customize the banner, but unless thorough checks
  #     are enabled, we'll just stop.
  if (!thorough_tests) exit(0);
}
# - IMAP.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
banner = get_imap_banner(port:port);
if (banner && " (IMail " >< banner)
{
  pat = "IMAP4 Server \(IMail ([0-9.]+) [0-9]+-[0-9]+\)";
  matches = egrep(pattern:pat, string:banner);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if it's < 9.20 (== 2006.2).
  if (ver && ver =~ "^([0-8]\.|9\.(0[0-9]$|1$))")
    security_hole(port);

  # nb: it's possible to customize the banner, but unless thorough checks
  #     are enabled, we'll just stop.
  if (!thorough_tests) exit(0);
}
