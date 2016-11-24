#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42373);
  script_version("$Revision: 1.3 $");

  script_cve_id(
    "CVE-2009-3864",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3876",
    "CVE-2009-3877"
  );
  script_bugtraq_id(36881);
  if (NASL_LEVEL >= 3000)
  {
    script_xref(name:"OSVDB", value:"59705");
    script_xref(name:"OSVDB", value:"59706");
    script_xref(name:"OSVDB", value:"59707");
    script_xref(name:"OSVDB", value:"59708");
    script_xref(name:"OSVDB", value:"59709");
    script_xref(name:"OSVDB", value:"59710");
    script_xref(name:"OSVDB", value:"59711");
    script_xref(name:"OSVDB", value:"59712");
    script_xref(name:"OSVDB", value:"59713");
    script_xref(name:"OSVDB", value:"59714");
    script_xref(name:"OSVDB", value:"59715");
    script_xref(name:"OSVDB", value:"59716");
    script_xref(name:"OSVDB", value:"59717");
    script_xref(name:"OSVDB", value:"59718");
  }

  script_name(english:"Sun Java Runtime Environment Multiple Vulnerabilities (269868 et al)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote Windows host contains a runtime environment that is\n",
      "affected by multiple vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The version of Sun Java Runtime Environment (JRE) installed on the\n",
      "remote host is earlier than 6 Update 17 / 5.0 Update 22 / 1.4.2_24 /\n",
      "1.3.1_27.  Such versions are potentially affected by the following\n",
      "security issues :\n",
      "\n",
      "  - The Java update mechanism on non-English versions does\n",
      "    not update the JRE when a new version is available. \n",
      "    (269868)\n",
      "\n",
      "  - A command execution vulnerability exists in the Java \n",
      "    runtime environment deployment toolkit. (269869)\n",
      "\n",
      "  - An issue in the Java web start installer may be\n",
      "    leveraged to allow an untrusted Java web start \n",
      "    application to run as a trusted application. (269870)\n",
      "\n",
      "  - Multiple buffer and integer overflow vulnerabilities.\n",
      "    (270474)\n",
      "\n",
      "  - A security vulnerability in the JRE with verifying HMAC\n",
      "    digests may allow authentication to be bypassed. \n",
      "    (270475)\n",
      "\n",
      "  - Two vulnerabilities in the JRE with decoding DER encoded\n",
      "    data and parsing HTTP headers may separately allow a\n",
      "    remote client to cause the JRE on the server to run out\n",
      "    of memory, resulting in a denial of service. (270476)"
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-269868-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-269869-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-269870-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-270474-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-270475-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-270476-1"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Update to Sun Java JDK / JRE 6 Update 17, JDK / JRE 5.0 Update 22,\n",
      "SDK / JRE 1.4.2_24, or SDK / JRE 1.3.1_27 or later and remove if \n",
      "necessary any affected versions."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/04"
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
    ver =~ "^1\.6\.0_(0[0-9]|1[0-6])[^0-9]?" ||
    ver =~ "^1\.5\.0_([01][0-9]|2[01])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_([01][0-9]|2[0-3][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|2[0-6][^0-9]?))"
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
