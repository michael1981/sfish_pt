#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description) {
  script_id(15611);
  script_version("$Revision: 1.6 $");
  script_bugtraq_id(11578);
  script_xref(name:"OSVDB", value:"11322");
  script_xref(name:"Secunia", value:"13062");

  script_name(english:"MailEnable Professional Webmail < 1.5.1 Unspecified Vulnerability");
  script_summary(english:"Checks for the version of MailEnable");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote webmail service has an unspecified vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of MailEnable Professional running on the remote host\n",
      "has an unspecified vulnerability in the webmail module."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to MailEnable Professional 1.5.1 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"   # assumes worst case scenario
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  script_dependencie("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_exclude_keys("SMTP/wrapped");

  exit(0);
}

include("global_settings.inc");
include("smtp_func.inc");

host = get_host_name();
port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

banner = get_smtp_banner(port:port);
str = egrep(pattern:"Mail(Enable| Enable SMTP) Service", string:banner);
if ( ! str ) exit(0);

ver = eregmatch(pattern:"Version: (0-)?([0-9][^-]+)-", string:str, icase:TRUE);
if (ver == NULL || ver[1] == NULL ) exit(1);
ver = ver[2];
if (ver =~ "^1\.(2.*|5)([^.]|$)") security_hole(port);

