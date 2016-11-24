#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
  script_id(12099);
  script_bugtraq_id(9824);
  script_version ("$Revision: 1.5 $");

  script_name(english:"F-Secure SSH Password Authentication Policy Evasion");
  script_summary(english:"F-Secure SSH version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SSH server has a security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "According to its banner, the version of F-Secure SSH running on the\n",
      "remote host allows a user to log in using a password, even though the\n",
      "server policy disallows it.  An attacker could exploit this flaw to\n",
      "run a dictionary attack against the SSH server."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to F-Secure SSH 3.1.0 build 9 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO); 
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

  script_require_ports("Services/ssh", 22);
  script_dependencie("ssh_detect.nasl");

  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ssh");
if (!port) port = 22;

banner = get_kb_item( "SSH/banner/" + port );
if(!banner) exit(0);

#
# SSH-2.0-3.2.0 F-Secure SSH Windows NT Server
# versions up to 3.1.0 affected
#
if(ereg(pattern:"^SSH-2.0-([12]\..*|3\.[01]\..*) F-Secure SSH", string:banner, icase:TRUE))
{ 
  security_warning(port);
}
