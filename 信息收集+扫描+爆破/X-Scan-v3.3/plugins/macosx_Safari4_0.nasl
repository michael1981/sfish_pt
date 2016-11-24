#TRUSTED 2f9e2dc0f4b0989604314cba1e94d080bda12e3b93a9dfe04fc67dffa78743c4b49351eee72bb91ee6fe8bf3247781bec08c68d8f2b2080bd8a126d73beab068ac4815abb11ad083faeb8906c8baf548860b4af75e0fc2a79057e2dc0c3a4de0e75b94ee314330bff0563eb2c104ae3259faae32fd3708ca3b5ef02922955b4c3151c25ea95f91ef1121b677bfd3e3cbb6a74d95cb54ee6d7909179f8cd3a72c831b881a32eeda0e761a138326a30118502a0db2f91f1ad9e5b7cd5877d60c47bdb63db0754d3ab95df96d8608c15593a06f9f3524f2e5a22e2fef8224a0deb7850617510dd92ac36f955853bf7ce06b211ee40ce6646fa5c8c9c81c6fdbe6f1d11cb580afe4740b0e34b629283d75ef7dd6eb58f80a5f3a3b3aa58d489175e64e51b4a628a947b2d71f1efd529a11d6a3006b88377d9bc565511393be79eead7f1ac06a418946fadba3cd32e0e3598024ad7d944f91282419b3e959c3991d627c86d195261fb408a020a7ae0ebf3805a28a599285ce783e154f8592040484d67440a2e818e05be30fbd1f5c0a24e297fe25ca00c6e67b886e8010d09f5be3b12b443d0b45d0357b7605d792672205c50b04690ca0e6b9707c72a6bdb743db3cb64efad11aa546d137bdb2ece73184f788762d0d7d659bb1059097969cf2f3d1359c664d4c9010f60d0e879a41782abc4f91c326edb9521f4daa1ad1d0944a86
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(39338);
  script_version("1.9");

  if (NASL_LEVEL >= 3000) 
  {
    script_cve_id(
      "CVE-2006-2783",
      "CVE-2008-1588",
      "CVE-2008-2320",
      "CVE-2008-3281",
      "CVE-2008-3529",
      "CVE-2008-3632",
      "CVE-2008-4225",
      "CVE-2008-4226",
      "CVE-2008-4231",
      "CVE-2008-4409",
      "CVE-2009-1681",
      "CVE-2009-1682",
      "CVE-2009-1684",
      "CVE-2009-1685",
      "CVE-2009-1686",
      "CVE-2009-1687",
      "CVE-2009-1688",
      "CVE-2009-1689",
      "CVE-2009-1690",
      "CVE-2009-1691",
      "CVE-2009-1693",
      "CVE-2009-1694",
      "CVE-2009-1695",
      "CVE-2009-1696",
      "CVE-2009-1697",
      "CVE-2009-1698",
      "CVE-2009-1699",
      "CVE-2009-1700",
      "CVE-2009-1701",
      "CVE-2009-1702",
      "CVE-2009-1703",
      "CVE-2009-1704",
      "CVE-2009-1708",
      "CVE-2009-1709",
      "CVE-2009-1710",
      "CVE-2009-1711",
      "CVE-2009-1712",
      "CVE-2009-1713",
      "CVE-2009-1714",
      "CVE-2009-1715",
      "CVE-2009-1718",
      "CVE-2009-2420",
      "CVE-2009-2421"
    );
    script_bugtraq_id(
      30487,
      31092,
      32326,
      33276,
      35260,
      35270,
      35271,
      35272,
      35283,
      35284,
      35309,
      35310,
      35311,
      35315,
      35317,
      35318,
      35319,
      35320,
      35321,
      35322,
      35325,
      35327,
      35328,
      35330,
      35331,
      35332,
      35333,
      35334,
      35340,
      35344,
      35348,
      35349,
      35350,
      35351,
      35353,
      35481,
      35482
    );
    script_xref(name:"OSVDB", value:"48472");
    script_xref(name:"OSVDB", value:"48569");
    script_xref(name:"OSVDB", value:"49993");
    script_xref(name:"OSVDB", value:"54972");
    script_xref(name:"OSVDB", value:"54973");
    script_xref(name:"OSVDB", value:"54975");
    script_xref(name:"OSVDB", value:"54981");
    script_xref(name:"OSVDB", value:"54982");
    script_xref(name:"OSVDB", value:"54983");
    script_xref(name:"OSVDB", value:"54984");
    script_xref(name:"OSVDB", value:"54985");
    script_xref(name:"OSVDB", value:"54986");
    script_xref(name:"OSVDB", value:"54987");
    script_xref(name:"OSVDB", value:"54988");
    script_xref(name:"OSVDB", value:"54989");
    script_xref(name:"OSVDB", value:"54990");
    script_xref(name:"OSVDB", value:"54991");
    script_xref(name:"OSVDB", value:"54992");
    script_xref(name:"OSVDB", value:"54993");
    script_xref(name:"OSVDB", value:"54994");
    script_xref(name:"OSVDB", value:"54996");
    script_xref(name:"OSVDB", value:"55004");
    script_xref(name:"OSVDB", value:"55005");
    script_xref(name:"OSVDB", value:"55006");
    script_xref(name:"OSVDB", value:"55008");
    script_xref(name:"OSVDB", value:"55009");
    script_xref(name:"OSVDB", value:"55010");
    script_xref(name:"OSVDB", value:"55011");
    script_xref(name:"OSVDB", value:"55013");
    script_xref(name:"OSVDB", value:"55014");
    script_xref(name:"OSVDB", value:"55015");
    script_xref(name:"OSVDB", value:"55022");
    script_xref(name:"OSVDB", value:"55023");
    script_xref(name:"OSVDB", value:"55027");
    script_xref(name:"OSVDB", value:"55769");
    script_xref(name:"OSVDB", value:"55783");
  }

  script_name(english:"Mac OS X : Safari < 4.0");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "The remote host contains a web browser that is affected by several\n",
      "vulnerabilities."
    )
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The version of Safari installed on the remote Mac OS X host is earlier\n",
      "than 4.0.  Such versions are potentially affected by numerous issues\n",
      "in the following components :\n",
      "\n",
      "  - CFNetwork\n",
      "  - libxml\n",
      "  - Safari\n",
      "  - WebKit"
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT3613"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2009/jun/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/advisories/17079"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Safari 4.0 or later."
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
  if (buf !~ "^[0-9]") exit(0);

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0);

uname = get_kb_item("Host/uname");
if (!uname) exit(0);


# Mac OS X 10.4 and 10.5.
if (egrep(pattern:"Darwin.* (8\.|9\.([0-6]\.|7\.0))", string:uname))
{
  cmd = 'cat /Applications/Safari.app/Contents/Info.plist|grep -A 1 CFBundleGetInfoString| tail -n 1 | sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\'|awk \'{print $1}\'|sed \'s/,//g\'';
  version = exec(cmd:cmd);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] < 4)
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
}
