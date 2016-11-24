#
#  (C) Tenable Network Security
#
# @DEPRECATED@
#
# Deprecated by java_jre_multiple_applet_vulnerability.nasl
# Disabled on 2009-10-09
exit(0);


if(description)
{
 script_id(15821);

 script_bugtraq_id(11726, 11766);
 script_cve_id("CVE-2004-1029");
 script_xref(name:"IAVA", value:"2004-b-0015");
 script_xref(name:"OSVDB", value:"12095");

 script_version("$Revision: 1.10 $");

 name["english"] = "Sun JRE Java Plug-in JavaScript Security Restriction Bypass";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using a vulnerable version of Sun Java Runtime
Plug-in, an addon to many web browsers like Internet Explorer to
display java applets.

It has been reported that the Java JRE Plug-in Security can be bypassed.
As a result, an attacker may be able to exploit it by creating a malicious
Java applet to compromise the computer.

Additionally, a denial of service vulnerability is present in the remote
version of the JVM. An attacker could exploit it by creating an applet
which misuses the serialization API.

Solution: Upgrade to JRE 1.4.2_06 or 1.3.1_13
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Java JRE plugin";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2008 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}


include("global_settings.inc");


# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(0);

info = "";
foreach install (keys(installs))
{
  ver = install - "SMB/Java/JRE/";
  if (ver =~ "^1\.(3\.(0.*|1[^_].*|1_[0-9][^0-9].*|1_1[0-2].*)|4\.([0-1]\..*|2_0[0-5].*))") 
    info += '  - ' + ver + ', under ' + installs[install] + '\n';
}


# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on the\n",
      "remote host :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
