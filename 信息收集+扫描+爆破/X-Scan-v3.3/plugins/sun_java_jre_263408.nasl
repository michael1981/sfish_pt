#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40495);
  script_version("$Revision: 1.8 $");

  script_cve_id(
    "CVE-2009-0217",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2674",
    "CVE-2009-2675",
    "CVE-2009-2676"
  );
  script_bugtraq_id(35922, 35939, 35942, 35943, 35944, 35945, 35946, 35958);
  script_xref(name:"OSVDB", value:"56783");
  script_xref(name:"OSVDB", value:"56784");
  script_xref(name:"OSVDB", value:"56785");
  script_xref(name:"OSVDB", value:"56786");
  script_xref(name:"OSVDB", value:"56787");
  script_xref(name:"OSVDB", value:"56788");
  script_xref(name:"OSVDB", value:"56789");
  script_xref(name:"OSVDB", value:"57431");

  script_name(english:"Sun Java Runtime Environment Multiple Vulnerabilities (263408 et al)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a runtime environment that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is earlier than 6 Update 15 / 5.0 Update 20 / 1.4.2_22 /
1.3.1_26.  Such version are potentially affected by the following
security issues :

  - A vulnerability in the JRE audio system may allow system
    properties to be accessed. (263408)

  - A privilege escalation vulnerability may exist in the
    JRE SOCKS proxy implementation. (263409)

  - An integer overflow vulnerability when parsing JPEG
    images may allow an untrusted Java Web Start application
    to escalate privileges. (263428)

  - A vulnerability with verifying HMAC-based XML digital
    signatures in the XML Digital Signature implementation
    may allow authentication to be bypassed. (263429)

  - An integer overflow vulnerability with unpacking applets
    and Java Web start applications using the 'unpack200' JAR
    unpacking utility may allow an untrusted applet to
    escalate privileges. (263488)

  - An issue with parsing XML data may allow a remote client
    to create a denial-of-service condition. (263489)

  - Non-current versions of the 'JNLPAppletLauncher' may be
    re-purposed with an untrusted Java applet to write
    arbitrary files. (263490)

  - A vulnerability in the Active Template Library in
    various releases of Microsoft Visual Studio that is used
    by the Java Web Start ActiveX control can be leveraged
    to execute arbitrary code. (264648)");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263408-1");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263409-1");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263428-1");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263429-1");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263488-1");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263489-1");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-263490-1");
  script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-264648-1");

  script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK / JRE 6 Update 15, JDK / JRE 5.0 Update 20,
SDK / JRE 1.4.2_22, or SDK / JRE 1.3.1_26 or later and remove if
necessary any affected versions.");
  script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/05"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/05"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/05"
  );
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
if (isnull(installs)) exit(1, "The 'SMB/Java/JRE/' KB item is missing.");

info = "";
foreach install (keys(installs))
{
  ver = install - "SMB/Java/JRE/";
  if (
    ver =~ "^1\.6\.0_(0[0-9]|1[0-4])[^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-9])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_([01][0-9]|2[01][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-5][^0-9]?))"
  ) info += '  - ' + ver + ', under ' + installs[install] + '\n';
}

# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity > 0)
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
else exit(0, "The remote host is not affected");
