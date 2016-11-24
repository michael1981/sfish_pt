#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22314);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-4379");
  script_bugtraq_id(19885);
  script_xref(name:"OSVDB", value:"28576");

  script_name(english:"Ipswitch IMail Server SMTP Service Crafted RCPT String Remote Overflow");
  script_summary(english:"Checks version of Ipswitch IMail");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch Collaboration Suite / IMail Secure
Server / IMail Server, commercial messaging and collaboration suites
for Windows. 

According to its banner, the version of Ipswitch Collaboration Suite /
IMail Secure Server / IMail Server installed on the remote host has a
stack buffer overflow in its SMTP server component that can be
triggered by long strings within the characters '@' and ':'.  An
unauthenticated attacker may be able to leverage this flaw to crash
the SMTP service or even to execute arbitrary code remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-028.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-09/0093.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ics/updates/ics20061.asp" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/imail/releases/im20061.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2006.1 of the appropriate application." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


# Pull the version from the banner.
banner = get_smtp_banner(port:port);
if (banner && " (IMail " >< banner)
{
  pat = "^[0-9][0-9][0-9] .+ \(IMail ([0-9.]+) [0-9]+-[0-9]+\) NT-ESMTP Server";
  matches = egrep(pattern:pat, string:banner);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if it's < 9.1 (== 2006.1).
  if (ver && ver =~ "^([0-8]\.|9\.0)")
    security_hole(port);
}
