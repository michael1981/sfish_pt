#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38877);
  script_version("$Revision: 1.3 $");
  script_cve_id("CVE-2009-1490");
  script_bugtraq_id(34944);
  script_xref(name:"OSVDB", value:"54669");
  
  script_name(english:"Sendmail < 8.13.2 Mail X-Header Handling Remote Overflow");
  script_summary(english:"Checks the version of Sendmail");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by a buffer overflow
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Sendmail mail server
earlier than 8.13.2. Such versions are reportedly affected by a remote
buffer overflow vulnerability. An attacker could leverage this flaw to
execute arbitrary code with the privileges of the affected
application." );
  script_set_attribute(attribute:"see_also", value:"http://www.nmrc.org/~thegnome/blog/apr09/" );
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/releases/8.13.2" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail 8.13.2 or later." );
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english:"SMTP problems");
  script_dependencies("find_service1.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/smtp");
if(!port) port = 25;

banner = get_smtp_banner(port:port);

if(banner && "Sendmail" >< banner)
{
  matches = eregmatch(pattern:"Sendmail.*[^/]([0-9]+\.[0-9]+\.[0-9]+)", string:banner);
  if (matches)
  {
    version = matches[1];
    if (version =~ "^[0-7]\.[0-9\.]+|8\.([0-9]\.[0-9\.]+|1[0-2]\.[0-9\.]+|13\.[01])$")
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus found the following affected version of Sendmail installed on the \n",
          "remote host :\n",
          "\n",
          "  ", version, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
}
