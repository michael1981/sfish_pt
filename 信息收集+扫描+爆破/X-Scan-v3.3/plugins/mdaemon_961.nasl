#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25683);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-3622");
  script_bugtraq_id(24787);
  script_xref(name:"OSVDB", value:"37193");

  script_name(english:"MDaemon Server DomainPOP Malformed Message DoS");
  script_summary(english:"Checks version of MDaemon");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N MDaemon, a mail server for Windows. 

According to its banner, the version of MDaemon installed on the
remote host contains a vulnerability in its 'DomainPOP' Mail
Collection component that may cause it to crash while processing a
specially-crafted message.  An unauthenticated remote attacker may be
able to leverage this issue to deny service to legitimate users of the
application." );
 script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDaemon 9.6.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143);

  exit(0);
}


include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Try to get the version number from a banner.
ver = NULL;
#
# - SMTP.
if (isnull(ver))
{
  port = get_kb_item("Services/smtp");
  if (!port) port = 25;
  if (get_port_state(port))
  {
    banner = get_smtp_banner(port:port);
    if (banner && " ESMTP MDaemon " >< banner)
    {
      pat = " ESMTP MDaemon ([0-9][0-9.]+) ";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }
    }
  }
}
# - POP3
if (isnull(ver))
{
  port = get_kb_item("Services/pop3");
  if (!port) port = 110;
  if (get_port_state(port))
  {
    banner = get_pop3_banner(port:port);
    if (banner && " POP MDaemon " >< banner)
    {
      pat = " POP MDaemon( ready using UNREGISTERED SOFTWARE)? ([0-9][0-9.]+) ";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[2];
            break;
          }
        }
      }
    }
  }
}
# - IMAP.
if (isnull(ver))
{
  port = get_kb_item("Services/imap");
  if (!port) port = 143;
  if (get_port_state(port))
  {
    banner = get_imap_banner(port:port);
    if (banner && " MDaemon " >< banner)
    {
      pat = " IMAP.* MDaemon ([0-9][0-9.]+) ";
      matches = egrep(pattern:pat, string:banner);
      if (matches)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            ver = item[1];
            break;
          }
        }
      }
    }
  }
}


# There's a problem if the version is < 9.6.1.
if (ver)
{
  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("9.6.1", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      report = string(
        "\n",
        "The banner reports itself as MDaemon version ", ver, "."
      );
      security_note(port:port, extra:report);

      break;
    }
    else if (iver[i] > fix[i])
      break;
}
