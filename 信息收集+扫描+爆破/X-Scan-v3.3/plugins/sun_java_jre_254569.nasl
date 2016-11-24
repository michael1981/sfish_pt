#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");

if (description)
{
  script_id(36034);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CVE-2006-2426",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1102",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1105",
    "CVE-2009-1106",
    "CVE-2009-1107"
  );
  script_bugtraq_id(34240);
  script_xref(name:"OSVDB", value:"53164");
  script_xref(name:"OSVDB", value:"53165");
  script_xref(name:"OSVDB", value:"53166");
  script_xref(name:"OSVDB", value:"53167");
  script_xref(name:"OSVDB", value:"53168");
  script_xref(name:"OSVDB", value:"53169");
  script_xref(name:"OSVDB", value:"53170");
  script_xref(name:"OSVDB", value:"53171");
  script_xref(name:"OSVDB", value:"53172");
  script_xref(name:"OSVDB", value:"53173");
  script_xref(name:"OSVDB", value:"53174");
  script_xref(name:"OSVDB", value:"53175");
  script_xref(name:"OSVDB", value:"53176");
  script_xref(name:"OSVDB", value:"53177");
  script_xref(name:"OSVDB", value:"53178");

  script_name(english:"Sun Java Runtime Environment Multiple Vulnerabilities (254569 et al)");
  script_summary(english:"Checks version of Sun JRE");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a runtime environment that is
affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is earlier than 6 Update 13 / 5.0 Update 18 / 1.4.2_20 /
1.3.1_25. Such versions are potentially affected by the following
security issues :

  - A denial of service vulnerability affects the JRE LDAP
    implementation. (254569).

  - A remote code execution vulnerability in the JRE LDAP
    implementation may allow for arbitrary code to be run in
    the context of the affected LDAP client. (254569)

  - There are multiple integer and buffer overflow
    vulnerabilities when unpacking applets and Java Web
    Start applications using the 'unpack2000' utility.
    (254570)

  - There are multiple denial of service vulnerabilities
    related to the storing and processing of temporary font
    files. (254608)

  - A privilege-escalation vulnerability affects the Java
    Plug-in when deserializing applets. (254611)

  - A weakness in the Java Plug-in allows JavaScript loaded
    from the localhost to connect to arbitrary ports on the
    local system. (254611)

  - A vulnerability in the Java Plug-in allows malicious
    JavaScript code to exploit vulnerabilities in earlier
    versions of the JRE that have been loaded by an applet
    located on the same web page. (254611)

  - An issue exists in the Java Plug-in when parsing
    'crossdomain.xml' allows an untrusted applet to connect
    to an arbitrary site hosting a 'crossdomain.xml' file.
    (254611)

  - The Java Plug-in allows a malicious signed applet to
    obscure the contents of a security dialog. (254611)

  - The JRE Virtual Machine is affected by a
    privilege-escalation vulnerability. (254610)

  - There are multiple buffer overflow vulnerabilities
    involving the JRE's processing of PNG and GIF images.
    (254571)

  - There are multiple buffer overflow vulnerabilities
    involving the JRE's processing of fonts. (254571)

  - A denial of service vulnerability affected the JRE HTTP
    server implementation which could be used to cause a
    denial of service on a JAX-WS service endpoint. (254609)" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254569-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254570-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254571-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254608-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254609-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254610-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-254611-1" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/javase/6/webnotes/6u13.html" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/j2se/1.5.0/ReleaseNotes.html" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/j2se/1.4.2/ReleaseNotes.html" );
 script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK / JRE 6 Update 13, JDK / JRE 5.0 Update 18,
SDK / JRE 1.4.2_20, or SDK / JRE 1.3.1_25 or later and remove if
necessary any affected versions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

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
  if (
    ver =~ "^1\.6\.0_(0[0-9]|1[0-2])[^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-7])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_([01][0-9][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-4][^0-9]?))"
  ) info += '  - ' + ver + ', under ' + installs[install] + '\n';
}

# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) >  1) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on the \n",
      "remote host :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
