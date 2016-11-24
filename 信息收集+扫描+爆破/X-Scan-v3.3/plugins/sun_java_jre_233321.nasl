#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31356);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-1193");
  script_bugtraq_id(28083, 28125);
  script_xref(name:"OSVDB", value:"42598");
  script_xref(name:"Secunia", value:"29239");

  script_name(english:"Sun Java Runtime Environment Multiple Vulnerabilities (233321-233327)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is affected by one or more security issues :

  - Two vulnerabilities in the JRE VM may independently allow 
    an untrusted application or applet downloaded from a 
    website to elevate its privileges (233321).

  - When processing XSLT transformations, an untrusted
    application or applet downloaded from a website may
    be able to elevate its privileges or cause the JRE to
    crash (233322).

  - Three buffer overflows exist in Java Web Start (233323).

  - A vulnerability in the Java Plug-in may allow an applet
    download from a website to bypass the same origin policy
    and execute local applications (233324).

  - Multiple vulnerabilities in the JRE Image Processing 
    library may allow an untrusted application or applet
    to elevate its privileges or cause the JRE to crash
    (233325).

  - A vulnerability in the JRE may allow untrusted 
    JavaScript code to elevate its privileges through
    Java APIs (233326).

  - An as-yet unspecified buffer overflow exists in Java 
    Web Start (233327)." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-233321-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-233322-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-233323-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-233324-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-233325-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-233326-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-233327-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun JDK and JRE 6 Update 5 / JDK and JRE 5.0 Update 15 /
SDK and JRE 1.4.2_17 or later and remove if necessary any other
affected versions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
    ver =~ "^1\.6\.0_0[0-4][^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-4])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-6][^0-9]?))" ||
    ver =~ "^1\.3\."
  ) info += '  - ' + ver + ', under ' + installs[install] + '\n';
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
