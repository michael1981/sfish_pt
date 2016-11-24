#TRUSTED 4bad0fac8c8b32a5bf15cf0edd7330111b800fab5d5501b3785d0164fc5fc923632ff112c286ebf41b327a3cb60ec7d754b8b3f0b92719fa95f8987d522899b531db9ea87ffca535c191b93b64b740bbdd176fdc26b9c0a79f19f9a871452dfa9e0d84bc30a8ab3b671375778532ef195bf0df03ad8d3eda0ad47b4d28dae5500ada1521b7b2e0ea37a56a1922fc8d08d1d7238aaf89f6cfd9e2c5c41ee29071990d82db65ae7f45cc490d08fd568704ae498264c540f945bc9e462b9703f5a62971b902f0c9d8580ccd96981b682be9f6ecd09d9cb2ae048ecb56b2797aea0703e7ada0093dbfceda6310674965846ccff23c242207361f3de77c242071a56024bb900372c80048f093d9831f98774f40352fc42e6911536f18be6f8e3befc6437b0c03173739ba947599642e3ae6f9618f3efa113b4612000ab6427eef78757166b2195b937621137536da926ba840e6c1a1873ffb0402d4256abcba5970a604c07ccbffd5ba6b97080bd0551b88674dc0e3706448937032d1bd65a270dd1f16acdd708ad22b4460b5af621f78ba2d6398ea376cc705b1758f933994dc212f378980da21d2010c0e5be6fe286da002b08e52c0ff3bcc593b9eb4ee92c7fd173e3906ed6d649c7668fa4cd62c52c447c31b9e4bb97323f1a5afa1e83e9996fe513912b4006b69fea38dcd0619bf4745e5599f7b1cf5744b56fc277ae6070651
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(42477);
  script_version("1.3");

  script_cve_id(
    "CVE-2009-2414",
    "CVE-2009-2416",
    "CVE-2009-2816",
    "CVE-2009-2841",
    "CVE-2009-2842"
  );
  script_bugtraq_id(36994, 36996, 36997);
  script_xref(name:"OSVDB", value:"56985");
  script_xref(name:"OSVDB", value:"56990");
  script_xref(name:"OSVDB", value:"59940");
  script_xref(name:"OSVDB", value:"59941");
  script_xref(name:"OSVDB", value:"59942");

  script_name(english:"Mac OS X : Safari < 4.0.4");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Safari installed on the remote Mac OS X host is earlier
than 4.0.4.  Such versions are potentially affected by several issues :

  - Multiple use-after-free issues exist in libxml2, the
    most serious of which could lead to a program crash.
    (CVE-2009-2414, CVE-2009-2416)

  - An issue in the handling of navigations initiated via 
    the 'Open Image in New Tab', 'Open Image in New Window'
    or 'Open Link in New Tab' shortcut menu options could
    be exploited to load a local HTML file, leading to
    disclosure of sensitive information. (CVE-2009-2842)

  - An issue involving WebKit's inclusion of custom HTTP
    headers specified by a requesting page in preflight
    requests in support of Cross-Origin Resource Sharing
    can facilitate cross-site request forgery attacks. 
    (CVE-2009-2816)

  - WebKit fails to issue a resource load callback to 
    determine if a resource should be loaded when it
    encounters an HTML 5 Media Element pointing to an 
    external resource, which could lead to undesired
    requests to remote servers. (CVE-2009-2841)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3949"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/nov/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/18277"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0.4 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/11/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/11/11"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/11/12"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
  local_var buf, ret;

  if (islocalhost())
    buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);

uname = get_kb_item("Host/uname");
if (!uname) exit(0);


# Mac OS X 10.4, 10.5, and 10.6.
if (egrep(pattern:"Darwin.* (8\.|9\.[0-8]\.|10\.)", string:uname))
{
  cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(1, "Failed to get version of Safari.");

  version = chomp(version);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 4 ||
    (ver[0] == 4 && ver[1] == 0 && ver[2] < 4)
  )
  {
    if (get_kb_item("global_settings/report_verbosity") > 0)
    {
      report = string(
        "\n",
        "Nessus collected the following information about the current install\n",
        "of Safari on the remote host :\n",
        "\n",
        "  Version : ", version, "\n"
      );
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
  }
  else exit(0, "The remote host is not affected since Safari " + version + " is installed.");
}
