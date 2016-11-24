#
# (C) Tenable Network Security, Inc.
#


if (NASL_LEVEL < 3000) exit(0);



include("compat.inc");

if (description)
{
  script_id(35030);
  script_version("$Revision: 1.8 $");

  script_cve_id(
    "CVE-2008-2086",
    "CVE-2008-5339",
    "CVE-2008-5340",
    "CVE-2008-5341",
    "CVE-2008-5342",
    "CVE-2008-5343",
    "CVE-2008-5344",
    "CVE-2008-5345",
    "CVE-2008-5346",
    "CVE-2008-5347",
    "CVE-2008-5348",
    "CVE-2008-5349",
    "CVE-2008-5350",
    "CVE-2008-5351",
    "CVE-2008-5352",
    "CVE-2008-5353",
    "CVE-2008-5354",
    "CVE-2008-5355",
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5358",
    "CVE-2008-5359",
    "CVE-2008-5360"
  );
  script_bugtraq_id(30633, 32608, 32620, 32892);

  script_name(english:"Sun Java Runtime Environment Multiple Vulnerabilities (244986 et al)");
  script_summary(english:"Checks version of Sun JRE"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a runtime environment that is
affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host is earlier than 6 Update 11 / 5.0 Update 17 / 1.4.2_19 /
1.3.1_24.  Such versions are potentially affected by the following
security issues :

  - The JRE creates temporary files with insufficiently
    random names. (244986)

  - There are multiple buffer overflow vulnerabilities
    involving the JRE's image processing code, its 
    handling of GIF images, and its font processing.
    (244987)

  - It may be possible for an attacker to bypass security 
    checks due to the manner in which it handles the 
    'non-shortest form' of UTF-8 byte sequences.

  - There are multiple security vulnerabilities in Java 
    Web Start and Java Plug-in that may allow for privilege
    escalation. (244988)

  - The JRE Java Update mechanism does not check the digital
    signature of the JRE that it downloads. (244989)

  - A buffer overflow may allow an untrusted Java 
    application that is launched through the commandline to 
    escalate its privileges. (244990)

  - A vulnerability related to deserializing calendar 
    objects may allow an untrusted applet or application to
    escalate its privileges. (244991)

  - A buffer overflow affects the 'unpack200' JAR unpacking
    utility and may allow an untrusted applet or application
    to escalate its privileges with unpacking applets and 
    Java Web Start applications. (244992)

  - The UTF-8 decoder accepts encodings longer than the 
    'shortest' form. Although not a vulnerability per se, 
    it may be leveraged to exploit software that relies on 
    the JRE UTF-8 decoder to reject the 'non-shortest form'
    sequence. (245246)

  - An untrusted applet or application may be able to list
    the contents of the home directory of the user running 
    the applet or application. (246266)

  - A denial of service vulnerability may be triggered when
    the JRE handles certain RSA public keys. (246286)

  - A vulnerability may be triggered while authenticating
    users through Kerberos and lead to a system-wide denial
    of service due to excessive consumption of operating
    system resources. (246346)

  - Security vulnerabilities in the JAX-WS and JAXB packages
    where internal classes can be accessed may allow an 
    untrusted applet or application to escalate privileges. 
    (246366)

  - An untrusted applet or application when parsing zip
    files may be able to read arbitrary memory locations in
    the process that the applet or application is running.
    (246386)

  - The JRE allows code loaded from the local filesystem to
    access localhost. (246387)" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-244986-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-244987-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-244988-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-244989-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-244990-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-244991-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-244992-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-245246-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-246266-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-246286-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-246346-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-246366-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-246386-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-246387-1" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/javase/6/webnotes/6u11.html" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/j2se/1.5.0/ReleaseNotes.html" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/j2se/1.4.2/ReleaseNotes.html" );
 script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK / JRE 6 Update 11, JDK / JRE 5.0 Update 17, 
SDK / JRE 1.4.2_19, or SDK / JRE 1.3.1_24 or later and 
remove if necessary any affected versions." );
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
    ver =~ "^1\.6\.0_(0[0-9]|10)[^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-6])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-8][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-3][^0-9]?))"
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
