#TRUSTED 9ea9a9b54f2c235852017550393bdd20bdc03048f06ea9d0b3337d67e6fdba7f3ee26ee26b7b98bd7ffe7fa306832a96b040b65e041700ec814cfb4d931f8b587a6a335c82e029256a4427b166777c77a10b69f9158a5319d225623d2b55fc91e26f81e3bef78207fa6930b7b3084b5f1900e48412c4f394a444e4e80b9fecc7d7bf4c6ba2f6f9054e261652beb747aec7ed2b30d07ecd742e54e3f3e8340eb8e2a8cae3ec8c46d1f7e661ca60fb176453959156a096944c32788ad334fbaa442c2bb97e18c6f51156cba29d9f54420e6e5301deb4c44fa632006ae05da6707c5f7f9ec2b1d40341772e713167342e705e25f320b60e1fd6744a941fe12aebf672a7f63f23bd5485f6750e97cd24146861972959d9f9ed18ed260a235ed4d2acb6dfc44db60c387ecbdc5def5bd915161bad0c0556c52d689636b796fd12d5a14e6693683d9f91c7ccd2eb05ee37cb5e0c67bf73a9acbcaf9ebc08a461194d45a80f56a86a93d8c247ad98ec2dc30fe458123e9948b054967b128c3c005b2d83b168641df9b427cec90aa22757a3bfab5e526a4f4eeb3c62b5e7d5bcc154deacd7df84d3ecc593c9cc750014cee358a2a3dd4eaef84cd20a71d0560ba8321018653b6f1ad466a6f3213f5e060c5d01fb859ece9637af1c686ff6f878623a088c4206f50452227ae31ab50c321eadf890c72f29e5afe8946937591c5d50880976
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(39435);
  script_version("1.2");

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
    "CVE-2008-5356",
    "CVE-2008-5357",
    "CVE-2008-5359",
    "CVE-2008-5360",
    "CVE-2009-1093",
    "CVE-2009-1094",
    "CVE-2009-1095",
    "CVE-2009-1096",
    "CVE-2009-1097",
    "CVE-2009-1098",
    "CVE-2009-1099",
    "CVE-2009-1100",
    "CVE-2009-1101",
    "CVE-2009-1103",
    "CVE-2009-1104",
    "CVE-2009-1106",
    "CVE-2009-1107",
    "CVE-2009-1719"
  );
  script_bugtraq_id(32620, 32892, 32608, 34240, 35381);
  script_xref(name:"OSVDB", value:"53164");
  script_xref(name:"OSVDB", value:"53165");
  script_xref(name:"OSVDB", value:"53166");
  script_xref(name:"OSVDB", value:"53167");
  script_xref(name:"OSVDB", value:"53168");
  script_xref(name:"OSVDB", value:"53169");
  script_xref(name:"OSVDB", value:"53170");
  script_xref(name:"OSVDB", value:"53171");
  script_xref(name:"OSVDB", value:"53172");
  script_xref(name:"OSVDB", value:"53174");
  script_xref(name:"OSVDB", value:"53175");
  script_xref(name:"OSVDB", value:"53177");
  script_xref(name:"OSVDB", value:"53178");
  script_xref(name:"OSVDB", value:"56457");
  script_xref(name:"Secunia", value:"35118");

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 4");
  script_summary(english:"Checks version of the JavaVM framework");

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
      "The remote Mac OS X 10.5 host is running a version of Java for\n",
      "Mac OS X that is missing Update 4.\n\n",
      "The remote version of this software contains several security\n",
      "vulnerabilities.  A remote attacker could exploit these issues to\n",
      "bypass security restrictions, disclose sensitive information, cause a\n",
      "denial of service, or escalate privileges."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/Security-announce/2009/Jun/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Upgrade to Java for Mac OS X 10.5 Update 4 (JavaVM Framework 12.3.0)\n",
      "or later."
    )
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

uname = get_kb_item("Host/uname");
if (!uname) exit(0);

# Mac OS X 10.5 only.
if (egrep(pattern:"Darwin.* 9\.", string:uname))
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

  # Fixed in version 12.3.0
  if (
    ver[0] < 12 ||
    (ver[0] == 12 && ver[1] < 3)
  )
  {
    if (get_kb_item("global_settings/report_verbosity") > 0)
    {
      report = string(
        "\n",
        "Product           : JavaVM Framework\n",
        "Installed version : ", version, "\n",
        "Fix               : 12.3.0\n"
      );
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
  }
}

