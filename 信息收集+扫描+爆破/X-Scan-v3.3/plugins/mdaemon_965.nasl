#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(31640);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2008-1358");
  script_bugtraq_id(28245);
  script_xref(name:"milw0rm", value:"5248");
  script_xref(name:"OSVDB", value:"43111");
  script_xref(name:"Secunia", value:"29382");

  script_name(english:"MDaemon IMAP Server FETCH Command Remote Buffer Overflow");
  script_summary(english:"Checks version in MDaemon's banners");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N MDaemon, a mail server for Windows. 

According to its banner, the version of MDaemon installed on the
remote host contains a stack-based buffer overflow in its IMAP server
component that can be triggered via a FETCH command with a long BODY
data item.  An authenticated remote attacker may be able to leverage
this issue to crash the affected service or execute arbitrary code
subject to the privileges under which the service operates. 

Note that MDaemon by default runs as a service with SYSTEM privileges
under Windows so successful exploitation could result in a complete
compromise of the affected system." );
 script_set_attribute(attribute:"see_also", value:"http://files.altn.com/MDaemon/Release/RelNotes_en.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDaemon 9.6.5 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/smtp", 25, 366, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");


# Try to get the version number from a banner.
ver = NULL;
service = NULL;

# - SMTP.
if (isnull(ver))
{
  ports = get_kb_list("Services/smtp");
  if (isnull(ports)) ports = make_list(25, 366, 587);
  foreach port (ports)
  {
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
              service = "SMTP";
              break;
            }
          }
        }
      }
      if (isnull(ver) && !thorough_tests) exit(0);
    }
    if (!isnull(ver)) break;
  }
}
# - POP3
if (isnull(ver))
{
  ports = get_kb_list("Services/pop3");
  if (isnull(ports)) ports = make_list(110, 995);
  foreach port (ports)
  {
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
              service = "POP3";
              break;
            }
          }
        }
      }
      if (isnull(ver) && !thorough_tests) exit(0);
    }
    if (!isnull(ver)) break;
  }
}
# - IMAP.
if (isnull(ver))
{
  ports = get_kb_list("Services/imap");
  if (isnull(ports)) ports = make_list(143, 993);
  foreach port (ports)
  {
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
              service = "IMAP";
              break;
            }
          }
        }
      }
      if (isnull(ver) && !thorough_tests) exit(0);
    }
    if (!isnull(ver)) break;
  }
}


# There's a problem if the version is < 9.6.5.
if (ver)
{
  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  fix = split("9.6.5", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(iver); i++)
    if ((iver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "According to its ", service, " banner, the remote is running MDaemon version\n",
          ver, ".\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      break;
    }
    else if (iver[i] > fix[i])
      break;
}
