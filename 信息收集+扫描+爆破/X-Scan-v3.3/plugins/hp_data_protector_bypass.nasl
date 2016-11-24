#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(22225);
  script_version("$Revision: 1.9 $");
  script_cve_id("CVE-2006-4201");
  script_bugtraq_id(19495);
  script_xref(name:"OSVDB", value:"27943");

  script_name(english:"HP OpenView Storage Data Protector Backup Agent Arbitrary Remote Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host through the backup
agent." );
 script_set_attribute(attribute:"description", value:
"The remote version of HP OpenView Data Protector is vulnerable to an
authentication bypass attack.  By sending specially-crafted requests
to the remote host, an attacker may be able to execute unauthorized
Backup commands.  Due to the nature of the software, successful
exploitation of this vulnerability could result in remote code
execution." );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/673228" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf5c4b17" );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port. Otherwise, apply the set of patches for Data Protector
5.10 and 5.50 referenced in HP's advisory above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for Data Protector version");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_require_ports(5555);
  script_dependencies ("hp_data_protector_installed.nasl");
  script_require_keys ("Services/data_protector/version", "Services/data_protector/build");

  exit(0);
}

version = get_kb_item ("Services/data_protector/version");
build = get_kb_item ("Services/data_protector/build");

port = 5555;

if (!version || !build)
  exit (0);

if ((version == "unknown") || (build == "unknown"))
  exit (0);

vulnerable = FALSE;

if (version == "A.05.50")
{
 # unpatched version == build number
 if (egrep (pattern:"^[0-9]+", string:build))
   vulnerable = TRUE;

 # windows patch name (last vulnerable = DPWIN_00202)
 else if (egrep (pattern:"DPWIN_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"DPWIN_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build <= 202)
    vulnerable = TRUE;
 }
 # windows security patch (fixed in SSPNT550_110)
 else if (egrep (pattern:"SSPNT550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPNT550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 110)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in SSPSOL550_035)
 else if (egrep (pattern:"SSPSOL550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPSOL550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 35)
    vulnerable = TRUE;
 }
 # hp-ux security patch (fixed in SSPUX550_124)
 else if (egrep (pattern:"SSPUX550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPUX550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 124)
    vulnerable = TRUE;
 }
}
else if (version == "A.05.10")
{
 # unpatched version == build number
 if (egrep (pattern:"^[0-9]+", string:build))
   vulnerable = TRUE;

 # windows patch name (last vulnerable = DPWIN_00172)
 if (egrep (pattern:"DPWIN_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"DPWIN_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build <= 172)
    vulnerable = TRUE;
 }
 # windows security patch (fixed in SSPNT510_080)
 else if (egrep (pattern:"SSPNT550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPNT550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 80)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in SSPSOL510_018)
 else if (egrep (pattern:"SSPSOL510_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPSOL510_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 18)
    vulnerable = TRUE;
 }
 # hp-ux security patch (fixed in SSPUX510_94)
 else if (egrep (pattern:"SSPUX510_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPUX510_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 94)
    vulnerable = TRUE;
 }
}

if (vulnerable)
  security_hole(port);
