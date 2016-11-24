#
# (C) Tenable Network Security
#



include("compat.inc");

if (description) {
  script_id(19592);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-2798");
  script_bugtraq_id(14729);
  script_xref(name:"OSVDB", value:"19141");

  name["english"] = "OpenSSH GSSAPI Credential Disclosure Vulnerability";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is susceptible to an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH installed on the
remote host may allow GSSAPI credentials to be delegated to users who
log in using something other than GSSAPI authentication if
'GSSAPIDelegateCredentials' is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.mindrot.org/pipermail/openssh-unix-announce/2005-September/000083.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 4.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N" );
script_end_attributes();

 
  summary["english"] = "Checks for GSSAPI credential disclosure vulnerability in OpenSSH";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


include("backport.inc");


port = get_kb_item("Services/ssh");
if (!port) port = 22;


auth  =  get_kb_item("SSH/supportedauth/" + port);
if ( ! auth ) exit(0);
if ( "gssapi" >!< auth ) exit(0);

banner = get_kb_item("SSH/banner/" + port);
if (banner) {
  banner = tolower(get_backport_banner(banner:banner));
  if (banner =~ "openssh[-_]([0-3]\.|4\.[01])")
    security_note(port);
}
