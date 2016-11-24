#TRUSTED 00738b589633e2dac11653082e6eb726ddcfc269de5f6f87a6231d4c3c30d211243ab7f16449265af1b862f4dbfbf91eb01f11dccbc759f168e0b0a942539b9897e025e1841845bd7f7f3c0ffbef199580e1ef0253cc1221f34a0ed22fd3f9d741703fbda4b66259aea734737a624a73e28a305cf04eb57e4d433a72b5821b7b152bf1eb54d74f910f78d1ce8ebd1a8a37ba383c8415d388aaa67f00717d900bce1754f4842cf1b5a5f1b431f74f195ede9fe0e0a3d0b7f40f0db117ba5c4aed49b612c2dbbd92c71a48ba208767081679c419dc34026abb408c0ba35a3e783ecfdf05979cc95fb20d78919f9ed9328b9266bd872d96b3ffb26e4de7bd4c72946480446424a733fc28206ac3ac4bec968a5f64aef807d694407106cda2a311916c2f20a9dbbfa9af111e4d5cc57d913f60e2c244d3ffdde236f767316ec90dbe4f24760ffbe88db6f1e2537720d3ec1c56c6368bde45a42447c4c696543a943d989bf2e752475a6870e10a4bfddd6cfc7a10a9f508c43cfd00444820ae131504ebd514c8e0daa1b29e1be5d8e81eb2c7eca3a812249af01b316774e6f07d46920614ba9f2d12bc3cf3aa3852e26f7d15a1084d3fe60e77ee1cc28355abc8f37153c9e68c63862ea0a07d2acc91a49816d779f49526cd8972fb344e5bcecf3f4fc59ead326724cda248cc3a05a68609e68aea0c97dfd9084f29b366583eeeb7d8
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(39766);
  script_version("1.2");

  if (NASL_LEVEL >= 3000) 
  {
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
      "CVE-2008-5348",
      "CVE-2008-5349",
      "CVE-2008-5350",
      "CVE-2008-5351",
      "CVE-2008-5352",
      "CVE-2008-5353",
      "CVE-2008-5354",
      "CVE-2008-5356",
      "CVE-2008-5357",
      "CVE-2008-5359",
      "CVE-2008-5360",
      "CVE-2009-1093",
      "CVE-2009-1094",
      "CVE-2009-1095",
      "CVE-2009-1096",
      "CVE-2009-1098",
      "CVE-2009-1099",
      "CVE-2009-1100",
      "CVE-2009-1101",
      "CVE-2009-1103",
      "CVE-2009-1104",
      "CVE-2009-1107"
    );
  }
  script_bugtraq_id(32892, 342401);

  script_name(english:"Mac OS X : Java for Mac OS X 10.4 Release 9");
  script_summary(english:"Check for Java Release 9 on Mac OS X 10.4");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host has a version of Java that is affected by multiple\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote Mac OS X 10.4 host is running a version of Java for Mac OS\n",
      "X older than release 9.\n",
      "\n",
      "The remote version of this software contains several security\n",
      "vulnerabilities.  A remote attacker could exploit these issues to\n",
      "bypass security restrictions, disclose sensitive information, cause a\n",
      "denial of service, or escalate privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/Security-announce/2009/Jun//msg00004.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.4 release 9."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread(cmd:"bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(0);
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);


# Mac OS X 10.4.11 only.
uname = get_kb_item("Host/uname");
if (egrep(pattern:"Darwin.* 8\.11\.", string:uname))
{
  plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
  cmd = string(
    "cat ", plist, " | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version = exec(cmd:cmd);
  if (!strlen(version)) exit(0);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Fixed in version 11.9.0.
  if (
    ver[0] < 11 ||
    (ver[0] == 11 && ver[1] < 9)
  ) security_hole(0);
}
